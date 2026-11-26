// Windows outer guard for one browser-harness process tree.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace LaunchBound {
    internal sealed class OuterCensus {
        internal int Active;
        internal ulong WorkingSet;
    }
    internal sealed class OuterCensusChangedException : InvalidOperationException { }
    public sealed class OuterAdmissionSample {
        public long ElapsedMilliseconds { get; set; }
        public ulong AvailableBytes { get; set; }
    }
    public sealed class OuterResult {
        public bool Success { get; internal set; }
        public bool CleanupConfirmed { get; internal set; }
        public string FailurePhase { get; internal set; }
        public string FailureStep { get; internal set; }
        public string FailureKind { get; internal set; }
        public int? NativeErrorCode { get; internal set; }
        public bool AbortFailed { get; internal set; }
        public bool CloseFailed { get; internal set; }
        public List<OuterAdmissionSample> AdmissionSamples { get; } = new List<OuterAdmissionSample>();
        public int RuntimeSamples { get; internal set; }
        public int CensusRetries { get; internal set; }
        public ulong PeakWorkingSetBytes { get; internal set; }
        public ulong? MinimumAvailableBytes { get; internal set; }
    }

    // Only tests compiled into this assembly can replace this implementation.
    internal abstract class OuterPlatform {
        internal virtual string DiagnosticStep { get { return null; } }
        internal abstract long Milliseconds { get; }
        internal abstract void Sleep(int milliseconds);
        internal abstract ulong Available();
        internal abstract void Start(string executable, string[] arguments);
        internal abstract OuterCensus Census();
        internal abstract bool RootExited(out uint exitCode);
        internal abstract void CheckStreams();
        internal abstract bool StreamsComplete();
        internal abstract void Abort();
        internal abstract void Close();
    }

    public static class OuterBrowserSupervisor {
        const ulong GiB = 1024UL * 1024 * 1024;
        internal const ulong JobLimit = 2 * GiB, Floor = 3 * GiB, Admission = 5 * GiB + GiB / 4;
        internal const int Deadline = 240000, Interval = 500;

        public static OuterResult Run(string executable, string[] arguments) {
            var report = new OuterResult();
            if (OperatingSystem.IsWindows()) RunCore(executable, arguments, new OuterWindows(), report);
            return report;
        }

        internal static int RunCore(string executable, string[] arguments, OuterPlatform platform, OuterResult report = null) {
            bool success = false, cleaned = false;
            string phase = "admission";
            try {
                for (int i = 0; i < 5; i++) {
                    if (i != 0) {
                        long until = checked(platform.Milliseconds + Interval);
                        while (platform.Milliseconds < until)
                            platform.Sleep((int)Math.Min(Interval, until - platform.Milliseconds));
                    }
                    ulong available = platform.Available();
                    report?.AdmissionSamples.Add(new OuterAdmissionSample { ElapsedMilliseconds = platform.Milliseconds, AvailableBytes = available });
                    if (available <= Admission) throw new InvalidOperationException();
                }
                long started = platform.Milliseconds;
                phase = "start";
                platform.Start(executable, arguments);
                while (true) {
                    phase = "runtime-deadline";
                    long sampleStarted = platform.Milliseconds;
                    if (sampleStarted - started >= Deadline) throw new TimeoutException();
                    phase = "runtime-memory";
                    ulong available = platform.Available();
                    if (report != null) {
                        report.RuntimeSamples++;
                        if (!report.MinimumAvailableBytes.HasValue || available < report.MinimumAvailableBytes) report.MinimumAvailableBytes = available;
                    }
                    if (available < Floor) throw new InvalidOperationException();
                    phase = "runtime-streams";
                    platform.CheckStreams();
                    phase = "runtime-census";
                    OuterCensus census;
                    while (true) {
                        try { census = platform.Census(); break; }
                        catch (OuterCensusChangedException) {
                            if (platform.Milliseconds - sampleStarted >= Interval) throw;
                            if (report != null) report.CensusRetries++;
                            platform.Sleep(1);
                            if (platform.Milliseconds - sampleStarted >= Interval) throw;
                        }
                    }
                    if (census == null || census.Active < 0) throw new InvalidOperationException();
                    if (report != null) report.PeakWorkingSetBytes = Math.Max(report.PeakWorkingSetBytes, census.WorkingSet);
                    if (census.WorkingSet > JobLimit) throw new InvalidOperationException();
                    phase = "root-exit";
                    uint code;
                    if (platform.RootExited(out code)) {
                        if (code != 0 || census.Active != 0 || !platform.StreamsComplete()) throw new InvalidOperationException();
                        // A second stable census closes the root-exit/accounting race.
                        phase = "terminal-census";
                        OuterCensus final = platform.Census();
                        ulong finalAvailable = platform.Available();
                        if (report != null && (!report.MinimumAvailableBytes.HasValue || finalAvailable < report.MinimumAvailableBytes))
                            report.MinimumAvailableBytes = finalAvailable;
                        if (final == null || final.Active != 0 || final.WorkingSet != 0 ||
                            finalAvailable < Floor || platform.Milliseconds - started >= Deadline) throw new InvalidOperationException();
                        success = true;
                        cleaned = true;
                        break;
                    }
                    long remaining = Interval - (platform.Milliseconds - sampleStarted);
                    if (remaining <= 0) throw new TimeoutException();
                    platform.Sleep((int)remaining);
                }
            } catch (Exception error) {
                success = false;
                if (report != null) {
                    report.FailurePhase = phase;
                    report.FailureStep = phase == "runtime-census" || phase == "terminal-census" ? platform.DiagnosticStep : null;
                    report.FailureKind = error is TimeoutException ? "timeout" :
                        error is Win32Exception ? "native" : error is IOException ? "io" :
                        error is ArgumentException ? "argument" : error is InvalidOperationException ? "state" : "execution";
                    if (error is Win32Exception native) report.NativeErrorCode = native.NativeErrorCode;
                }
            }
            if (!success) {
                try { platform.Abort(); cleaned = true; } catch { if (report != null) report.AbortFailed = true; }
            }
            try { platform.Close(); } catch { success = false; cleaned = false; if (report != null) report.CloseFailed = true; }
            if (report != null) { report.Success = success; report.CleanupConfirmed = cleaned; }
            return success ? 0 : 1;
        }
    }

    internal class OuterWindows : OuterPlatform {
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly object gate = new object();
        KernelHandle job, root, thread, input, outWrite, errWrite;
        SafeFileHandle outRead, errRead;
        Task<bool> stdout, stderr;
        Thread watchdog;
        readonly ManualResetEvent watchdogStop = new ManualResetEvent(false);
        bool assigned, created, creationUncertain, expired, closed;
        string diagnosticStep;
        internal override string DiagnosticStep { get { return diagnosticStep; } }
        long startTime;
        internal override long Milliseconds { get { return clock.ElapsedMilliseconds; } }
        internal override void Sleep(int milliseconds) { Thread.Sleep(milliseconds); }
        internal override ulong Available() {
            var value = new Native.SystemMemory { length = (uint)Marshal.SizeOf<Native.SystemMemory>() };
            Native.Check(Native.GlobalMemoryStatusEx(ref value));
            if (value.total == 0 || value.available > value.total) throw new InvalidOperationException();
            return value.available;
        }
        T Query<T>(int kind) where T : struct {
            int size = Marshal.SizeOf<T>(); IntPtr p = Marshal.AllocHGlobal(size);
            try { Native.Check(Native.QueryInformationJobObject(job, kind, p, size, IntPtr.Zero)); return Marshal.PtrToStructure<T>(p); }
            finally { Marshal.FreeHGlobal(p); }
        }
        internal virtual int[] Pids() {
            for (int capacity = 32; capacity <= 32768; capacity *= 2) {
                int size = checked(8 + capacity * IntPtr.Size); IntPtr p = Marshal.AllocHGlobal(size);
                try {
                    if (!Native.QueryInformationJobObject(job, 3, p, size, IntPtr.Zero)) {
                        if (Marshal.GetLastWin32Error() == 234) continue;
                        throw new InvalidOperationException();
                    }
                    int assignedCount = Marshal.ReadInt32(p), count = Marshal.ReadInt32(p, 4);
                    if (count < 0 || count > capacity || assignedCount != count) throw new InvalidOperationException();
                    int[] ids = new int[count];
                    for (int i = 0; i < count; i++) {
                        ids[i] = checked((int)Marshal.ReadIntPtr(p, 8 + i * IntPtr.Size).ToInt64());
                        if (ids[i] <= 0) throw new InvalidOperationException();
                    }
                    Array.Sort(ids);
                    if (ids.Distinct().Count() != ids.Length) throw new InvalidOperationException();
                    return ids;
                } finally { Marshal.FreeHGlobal(p); }
            }
            throw new InvalidOperationException();
        }
        static SafeFileHandle Pipe(ref Native.SA sa, out KernelHandle writer) {
            IntPtr read, write; Native.Check(Native.CreatePipe(out read, out write, ref sa, 0));
            writer = new KernelHandle(write); var reader = new SafeFileHandle(read, true);
            try {
                Native.Check(Native.SetHandleInformation(read, 1, 0));
                uint readFlags, writeFlags;
                Native.Check(Native.GetHandleInformation(read, out readFlags));
                Native.Check(Native.GetHandleInformation(write, out writeFlags));
                if ((readFlags & 1) != 0 || (writeFlags & 1) == 0) throw new InvalidOperationException();
                return reader;
            }
            catch { reader.Dispose(); writer.Dispose(); throw; }
        }
        static Task<bool> Pump(SafeFileHandle pipe, Stream destination) {
            return Task.Run(() => {
                bool complete = false;
                try {
                    var buffer = new byte[8192];
                    while (true) {
                        uint available, count;
                        if (!Native.PeekNamedPipe(pipe, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) {
                            if (Marshal.GetLastWin32Error() == 109) { destination.Flush(); complete = true; }
                            break;
                        }
                        if (available == 0) { Thread.Sleep(5); continue; }
                        Native.Check(Native.ReadFile(pipe, buffer, Math.Min(available, (uint)buffer.Length), out count, IntPtr.Zero));
                        if (count == 0) break;
                        destination.Write(buffer, 0, checked((int)count));
                    }
                } catch { complete = false; }
                finally {
                    try {
                        if (!Native.CloseHandle(pipe.DangerousGetHandle())) complete = false;
                        else pipe.SetHandleAsInvalid();
                    } catch { complete = false; }
                    finally { pipe.Dispose(); }
                }
                return complete;
            });
        }
        static bool CloseChecked(KernelHandle handle) {
            if (handle == null || handle.IsClosed || handle.IsInvalid) return true;
            bool closed = false;
            try {
                closed = Native.CloseHandle(handle.DangerousGetHandle());
                if (closed) handle.SetHandleAsInvalid();
            } catch { closed = false; }
            finally { handle.Dispose(); }
            return closed;
        }
        void CheckDeadline() {
            if (Volatile.Read(ref expired) || Milliseconds - startTime >= OuterBrowserSupervisor.Deadline) throw new TimeoutException();
        }
        internal virtual bool Assign() { return Native.AssignProcessToJobObject(job, root); }
        internal virtual bool Member(KernelHandle process) {
            bool member; Native.Check(Native.IsProcessInJob(process.DangerousGetHandle(), job.DangerousGetHandle(), out member)); return member;
        }
        internal virtual uint Resume() { return Native.ResumeThread(thread); }
        internal virtual bool Memory(KernelHandle process, ref Native.Memory value) { return Native.K32GetProcessMemoryInfo(process, ref value, value.size); }
        internal virtual Native.Accounting Accounting() { return Query<Native.Accounting>(1); }
        internal virtual bool TerminateOriginal() { return Native.TerminateProcess(root, 125); }
        internal virtual uint WaitOriginal() { return Native.WaitForSingleObject(root, 5000); }
        internal virtual bool WaitForDeadline(int milliseconds) { return watchdogStop.WaitOne(milliseconds); }
        internal override void Start(string executable, string[] arguments) {
            if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable) || arguments == null ||
                arguments.Any(a => a == null || a.IndexOf('\0') >= 0)) throw new ArgumentException();
            string command = JobOwner.Quote(executable) + " " + String.Join(" ", arguments.Select(JobOwner.Quote));
            if (command.Length >= 32767) throw new ArgumentException();
            startTime = Milliseconds;
            job = new KernelHandle(Native.CreateJobObjectW(IntPtr.Zero, null)); Native.Check(!job.IsInvalid);
            uint flags; Native.Check(Native.GetHandleInformation(job.DangerousGetHandle(), out flags));
            if ((flags & 1) != 0) throw new InvalidOperationException();
            var limit = new Native.Extended { basic = new Native.BasicLimit { flags = 0x2200 }, job = new UIntPtr(OuterBrowserSupervisor.JobLimit) };
            Native.Check(Native.SetInformationJobObject(job, 9, ref limit, Marshal.SizeOf<Native.Extended>()));
            VerifyPolicy();
            bool selfMember; Native.Check(Native.IsProcessInJob(Native.GetCurrentProcess(), job.DangerousGetHandle(), out selfMember));
            if (selfMember) throw new InvalidOperationException();
            var sa = new Native.SA { size = Marshal.SizeOf<Native.SA>(), inherit = true };
            outRead = Pipe(ref sa, out outWrite); errRead = Pipe(ref sa, out errWrite);
            input = new KernelHandle(Native.CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0, IntPtr.Zero));
            Native.Check(!input.IsInvalid);
            uint inputFlags; Native.Check(Native.GetHandleInformation(input.DangerousGetHandle(), out inputFlags));
            if ((inputFlags & 1) == 0 || input.DangerousGetHandle() == outWrite.DangerousGetHandle() ||
                input.DangerousGetHandle() == errWrite.DangerousGetHandle() ||
                outWrite.DangerousGetHandle() == errWrite.DangerousGetHandle()) throw new InvalidOperationException();
            IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero; bool initialized = false;
            try {
                UIntPtr bytes = UIntPtr.Zero;
                Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                if (bytes.ToUInt64() == 0 || bytes.ToUInt64() > 65536) throw new InvalidOperationException();
                attributes = Marshal.AllocHGlobal(checked((int)bytes.ToUInt64()));
                Native.Check(Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes)); initialized = true;
                handles = Marshal.AllocHGlobal(3 * IntPtr.Size);
                Marshal.WriteIntPtr(handles, input.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, outWrite.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, errWrite.DangerousGetHandle());
                Native.Check(Native.UpdateProcThreadAttribute(attributes, 0, new UIntPtr(0x20002), handles, new UIntPtr((uint)(3 * IntPtr.Size)), IntPtr.Zero, IntPtr.Zero));
                var si = new Native.SIX { startup = new Native.SI { cb = Marshal.SizeOf<Native.SIX>(), flags = 0x100, input = input.DangerousGetHandle(), output = outWrite.DangerousGetHandle(), error = errWrite.DangerousGetHandle() }, attributes = attributes };
                lock (gate) {
                    CheckDeadline();
                    watchdog = new Thread(() => {
                        int delay = Math.Max(0, OuterBrowserSupervisor.Deadline - (int)(Milliseconds - startTime));
                        if (WaitForDeadline(delay)) return;
                        lock (gate) {
                            if (closed) return;
                            expired = true;
                            try { Terminate(); } catch { }
                        }
                    }) { IsBackground = true, Name = "Outer browser deadline" };
                    watchdog.Start();
                    Native.PI pi;
                    bool createdOk = Native.CreateProcessW(executable, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true, 0x08080004, IntPtr.Zero, Path.GetDirectoryName(executable), ref si, out pi);
                    root = new KernelHandle(pi.process); thread = new KernelHandle(pi.thread); created = !root.IsInvalid;
                    creationUncertain = !created && (createdOk || !thread.IsInvalid);
                    Native.Check(createdOk);
                    if (root.IsInvalid || thread.IsInvalid || pi.pid == 0) throw new InvalidOperationException();
                    var image = new StringBuilder(32768); uint imageLength = (uint)image.Capacity;
                    Native.Check(Native.QueryFullProcessImageNameW(root.DangerousGetHandle(), 0, image, ref imageLength));
                    if (Native.GetProcessId(root.DangerousGetHandle()) != pi.pid ||
                        !String.Equals(Path.GetFullPath(image.ToString()), Path.GetFullPath(executable), StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException();
                    CheckDeadline();
                    Native.Check(Assign()); assigned = true;
                    if (!Member(root) || !Pids().Contains(checked((int)pi.pid)) || Query<Native.Accounting>(1).active != 1) throw new InvalidOperationException();
                    VerifyPolicy();
                    if (!CloseChecked(outWrite)) throw new InvalidOperationException(); outWrite = null;
                    if (!CloseChecked(errWrite)) throw new InvalidOperationException(); errWrite = null;
                    if (!CloseChecked(input)) throw new InvalidOperationException(); input = null;
                    stdout = Pump(outRead, Console.OpenStandardOutput()); outRead = null;
                    stderr = Pump(errRead, Console.OpenStandardError()); errRead = null;
                    CheckDeadline();
                    if (Available() < OuterBrowserSupervisor.Floor) throw new InvalidOperationException();
                }
                CheckDeadline();
                if (Resume() != 1) throw new InvalidOperationException();
                CheckDeadline();
            } finally {
                if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            }
        }
        void VerifyPolicy() {
            var limit = Query<Native.Extended>(9);
            if (limit.basic.flags != 0x2200 || limit.job.ToUInt64() != OuterBrowserSupervisor.JobLimit || Query<uint>(4) != 0) throw new InvalidOperationException();
        }
        internal override OuterCensus Census() {
            diagnosticStep = "deadline";
            CheckDeadline();
            diagnosticStep = "accounting-before";
            var before = Accounting();
            diagnosticStep = "process-list-before";
            int[] ids = Pids(); ulong sum = 0;
            var retained = new List<KernelHandle>();
            try {
                foreach (int pid in ids) {
                    diagnosticStep = "process-open";
                    var process = new KernelHandle(Native.OpenProcess(0x100410, false, pid)); retained.Add(process);
                    Native.Check(!process.IsInvalid);
                    diagnosticStep = "process-membership";
                    if (!Member(process) || Native.WaitForSingleObject(process, 0) != 258) throw new InvalidOperationException();
                    var memory = new Native.Memory { size = (uint)Marshal.SizeOf<Native.Memory>() };
                    diagnosticStep = "process-memory";
                    Native.Check(Memory(process, ref memory));
                    if (memory.ws.ToUInt64() == 0) throw new InvalidOperationException();
                    sum = checked(sum + memory.ws.ToUInt64());
                    if (sum > OuterBrowserSupervisor.JobLimit) throw new InvalidOperationException();
                }
                diagnosticStep = "process-list-after";
                int[] afterIds = Pids();
                diagnosticStep = "accounting-after";
                var after = Accounting();
                diagnosticStep = "accounting-bracket";
                if (before.total != after.total || before.terminated != after.terminated || !ids.SequenceEqual(afterIds)) {
                    diagnosticStep = "process-churn";
                    throw new OuterCensusChangedException();
                }
                if (before.active != ids.Length || after.active != ids.Length) {
                    diagnosticStep = "accounting-count";
                    throw new InvalidOperationException();
                }
                diagnosticStep = "process-liveness";
                foreach (var process in retained) if (Native.WaitForSingleObject(process, 0) != 258) throw new InvalidOperationException();
                diagnosticStep = "deadline";
                CheckDeadline();
                return new OuterCensus { Active = ids.Length, WorkingSet = sum };
            } finally {
                bool allClosed = true;
                foreach (var process in retained) if (!CloseChecked(process)) allClosed = false;
                if (!allClosed) { diagnosticStep = "process-close"; throw new InvalidOperationException(); }
            }
        }
        internal override bool RootExited(out uint code) {
            uint wait = Native.WaitForSingleObject(root, 0); code = 0;
            if (wait == 258) return false;
            if (wait != 0) throw new InvalidOperationException();
            Native.Check(Native.GetExitCodeProcess(root, out code)); return true;
        }
        internal override void CheckStreams() {
            if (stdout == null || stderr == null ||
                (stdout.IsCompleted && (!stdout.IsCompletedSuccessfully || !stdout.Result)) ||
                (stderr.IsCompleted && (!stderr.IsCompletedSuccessfully || !stderr.Result))) throw new IOException();
        }
        internal override bool StreamsComplete() {
            if (stdout == null || stderr == null) return false;
            // Root exit alone is insufficient; pipe EOF must also be observed.
            int remaining = Math.Max(0, OuterBrowserSupervisor.Deadline - (int)(Milliseconds - startTime));
            if (!Task.WaitAll(new Task[] { stdout, stderr }, Math.Min(5000, remaining))) return false;
            return stdout.Result && stderr.Result;
        }
        void Terminate() {
            if (assigned) Native.Check(Native.TerminateJobObject(job, 125));
            else if (created) Native.Check(TerminateOriginal());
        }
        internal override void Abort() {
            lock (gate) { Terminate(); }
            if (creationUncertain) throw new InvalidOperationException();
            if (created) {
                if (WaitOriginal() != 0) throw new InvalidOperationException();
                if (assigned) {
                    var wait = Stopwatch.StartNew();
                    while (true) {
                        var before = Query<Native.Accounting>(1); int[] ids = Pids(); var after = Query<Native.Accounting>(1);
                        if (before.active == 0 && after.active == 0 && ids.Length == 0 && before.total == after.total && before.terminated == after.terminated) break;
                        if (wait.ElapsedMilliseconds >= 5000) throw new InvalidOperationException();
                        Thread.Sleep(10);
                    }
                }
            }
        }
        internal override void Close() {
            bool failed;
            lock (gate) {
                if (closed) throw new InvalidOperationException();
                closed = true; watchdogStop.Set();
                failed = expired || (created && Milliseconds - startTime >= OuterBrowserSupervisor.Deadline);
                foreach (var handle in new KernelHandle[] { outWrite, errWrite, input, thread, root, job }) {
                    if (!CloseChecked(handle)) failed = true;
                }
                try { outRead?.Dispose(); } catch { failed = true; }
                try { errRead?.Dispose(); } catch { failed = true; }
            }
            if (watchdog != null && !watchdog.Join(5000)) failed = true;
            if (watchdog == null || !watchdog.IsAlive) watchdogStop.Dispose();
            if (created && Milliseconds - startTime >= OuterBrowserSupervisor.Deadline) failed = true;
            if (failed) throw new InvalidOperationException();
        }
    }
}
