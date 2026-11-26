using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using LaunchBound;

namespace OuterSupervisorTests {
    internal sealed class Fake : OuterPlatform {
        internal override string DiagnosticStep { get { return "test-census"; } }
        internal long Now;
        internal int Samples, Sleeps, Aborts, Closes, CensusCalls;
        internal int CensusChangesRemaining;
        internal bool AlwaysChangeCensus;
        internal bool Started, Exited = true, Streams = true, ThrowStart, ThrowCensus, ThrowStream, ThrowExit, ThrowAbort, ThrowClose, ThrowAvailable;
        internal ulong AdmissionValue = OuterBrowserSupervisor.Admission + 1, RuntimeValue = OuterBrowserSupervisor.Floor;
        internal int Active;
        internal ulong WorkingSet;
        internal uint ExitCode;
        internal long StartedAt;
        internal readonly List<long> SampleTimes = new List<long>();
        internal bool CompleteAfterSleep;
        internal override long Milliseconds { get { return Now; } }
        internal override void Sleep(int ms) {
            if (ms <= 0) throw new Exception(); Now += ms; Sleeps++;
            if (CompleteAfterSleep && Started) { Exited = true; Active = 0; WorkingSet = 0; }
        }
        internal override ulong Available() {
            SampleTimes.Add(Now); if (ThrowAvailable) throw new Exception(); return Samples++ < 5 ? AdmissionValue : RuntimeValue;
        }
        internal override void Start(string exe, string[] args) { Started = true; StartedAt = Now; if (ThrowStart) throw new Exception(); }
        internal override OuterCensus Census() {
            CensusCalls++;
            if (ThrowCensus) throw new Exception();
            if (AlwaysChangeCensus || CensusChangesRemaining-- > 0) throw new OuterCensusChangedException();
            return new OuterCensus { Active = Active, WorkingSet = WorkingSet };
        }
        internal override bool RootExited(out uint exitCode) { if (ThrowExit) throw new Exception(); exitCode = ExitCode; return Exited; }
        internal override void CheckStreams() { if (ThrowStream) throw new Exception(); }
        internal override bool StreamsComplete() { return Streams; }
        internal override void Abort() { Aborts++; if (ThrowAbort) throw new Exception(); }
        internal override void Close() { Closes++; if (ThrowClose) throw new Exception(); }
    }
    internal sealed class NativeFault : OuterWindows {
        internal string Fault;
        internal int Resumes, Assignments, Members, Memories, Rollbacks, Waits, Accounts, Enumerations;
        internal int MaxActive;
        internal bool RootExitObserved, AbortConfirmed;
        internal uint RollbackWait = uint.MaxValue;
        internal string DeadlineMarker;
        internal bool DeadlineReleased;
        internal override ulong Available() { return OuterBrowserSupervisor.Admission + 1; }
        internal override bool Assign() { Assignments++; return Fault == "assignment" ? false : base.Assign(); }
        internal override bool Member(KernelHandle process) {
            Members++;
            if (Fault == "membership" || (Fault == "membership-running" && Resumes > 0)) return false;
            if (Fault == "membership-unknown" && Resumes > 0) throw new InvalidOperationException();
            return base.Member(process);
        }
        internal override uint Resume() { Resumes++; return base.Resume(); }
        internal override bool Memory(KernelHandle process, ref Native.Memory value) {
            Memories++; if (Fault == "counter") return false;
            bool result = base.Memory(process, ref value);
            if (Fault == "zero-counter") value.ws = UIntPtr.Zero;
            return result;
        }
        internal override Native.Accounting Accounting() {
            Accounts++; var result = base.Accounting();
            if (Fault == "accounting") result.active++;
            return result;
        }
        internal override int[] Pids() {
            Enumerations++;
            if (Fault == "enumeration" && Resumes > 0) throw new InvalidOperationException();
            return base.Pids();
        }
        internal override OuterCensus Census() {
            OuterCensus value = base.Census(); MaxActive = Math.Max(MaxActive, value.Active); return value;
        }
        internal override bool RootExited(out uint code) {
            bool exited = base.RootExited(out code); RootExitObserved |= exited; return exited;
        }
        internal override void Abort() { base.Abort(); AbortConfirmed = true; }
        internal override bool TerminateOriginal() { Rollbacks++; return base.TerminateOriginal(); }
        internal override uint WaitOriginal() { Waits++; RollbackWait = base.WaitOriginal(); return RollbackWait; }
        internal override bool WaitForDeadline(int milliseconds) {
            if (Fault != "watchdog") return base.WaitForDeadline(milliseconds);
            var clock = Stopwatch.StartNew();
            while (clock.ElapsedMilliseconds < 10000 && !File.Exists(DeadlineMarker)) Thread.Sleep(10);
            DeadlineReleased = File.Exists(DeadlineMarker);
            return !DeadlineReleased;
        }
    }
    public static class Tests {
        static void Require(bool value, string name) { if (!value) throw new Exception(name); }
        static int Run(Fake f) { return OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), f); }
        public static void Contracts() {
            var good = new Fake(); Require(Run(good) == 0 && good.Samples == 7 && good.StartedAt == 2000 &&
                good.CensusCalls == 2 && good.Aborts == 0 && good.Closes == 1, "success and admission spacing");
            for (int i = 1; i < 5; i++) Require(good.SampleTimes[i] - good.SampleTimes[i-1] >= 500, "sample spacing");
            var report = new OuterResult(); var measured = new Fake();
            Require(OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), measured, report) == 0 &&
                report.Success && report.CleanupConfirmed && report.AdmissionSamples.Count == 5 &&
                report.RuntimeSamples == 1 && report.MinimumAvailableBytes == OuterBrowserSupervisor.Floor,
                "safe admission telemetry");
            var unconfirmed = new OuterResult(); var cleanupFault = new Fake { ThrowAbort = true, ThrowCensus = true };
            Require(OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), cleanupFault, unconfirmed) == 1 &&
                !unconfirmed.Success && !unconfirmed.CleanupConfirmed && unconfirmed.AbortFailed &&
                unconfirmed.FailurePhase == "runtime-census" && unconfirmed.FailureStep == "test-census" &&
                unconfirmed.FailureKind == "execution", "cleanup and sanitized failure telemetry");
            var closeReport = new OuterResult(); var closeFault = new Fake { ThrowClose = true };
            Require(OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), closeFault, closeReport) == 1 &&
                !closeReport.Success && !closeReport.CleanupConfirmed && closeReport.CloseFailed, "close failure telemetry");
            var churnReport = new OuterResult(); var churn = new Fake { CensusChangesRemaining = 2 };
            Require(OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), churn, churnReport) == 0 &&
                churnReport.CensusRetries == 2 && churn.CensusCalls == 4 && churn.Now - churn.StartedAt == 2,
                "brief observed churn retries inside one sampling interval");
            var sustainedReport = new OuterResult(); var sustained = new Fake { AlwaysChangeCensus = true };
            Require(OuterBrowserSupervisor.RunCore("unused", Array.Empty<string>(), sustained, sustainedReport) == 1 &&
                sustained.Now - sustained.StartedAt == OuterBrowserSupervisor.Interval && sustained.Aborts == 1 &&
                sustainedReport.FailurePhase == "runtime-census" && !sustainedReport.Success,
                "sustained churn fails closed within the sampling interval");
            var low = new Fake { AdmissionValue = OuterBrowserSupervisor.Admission };
            Require(Run(low) == 1 && !low.Started && low.Aborts == 1, "strict admission");
            foreach (var f in new[] {
                new Fake { ThrowStart = true }, new Fake { ThrowCensus = true }, new Fake { ThrowExit = true },
                new Fake { ThrowAvailable = true },
                new Fake { ThrowStream = true }, new Fake { Streams = false }, new Fake { ExitCode = 1 },
                new Fake { Active = 1 }, new Fake { Active = -1 },
                new Fake { RuntimeValue = OuterBrowserSupervisor.Floor - 1 },
                new Fake { WorkingSet = OuterBrowserSupervisor.JobLimit + 1 },
                new Fake { ThrowAbort = true, ThrowCensus = true }, new Fake { ThrowClose = true }
            }) Require(Run(f) == 1 && f.Closes == 1, "fail closed");
            var exact = new Fake { WorkingSet = OuterBrowserSupervisor.JobLimit };
            // A terminal census must have zero working set.
            Require(Run(exact) == 1, "terminal accounting");
            var boundary = new Fake { WorkingSet = OuterBrowserSupervisor.JobLimit, Active = 1, Exited = false, CompleteAfterSleep = true };
            Require(Run(boundary) == 0, "inclusive runtime limits");
            var deadline = new Fake { Exited = false, Active = 1 };
            Require(Run(deadline) == 1 && deadline.Now - deadline.StartedAt == OuterBrowserSupervisor.Deadline && deadline.Aborts == 1, "deadline");
        }
        public static void Native(string pwsh, string marker) {
            if (!OperatingSystem.IsWindows()) throw new Exception("Windows required");
            foreach (string fault in new[] { "assignment", "membership", "membership-running", "membership-unknown", "counter", "zero-counter", "accounting", "enumeration", "success" }) {
                if (File.Exists(marker)) File.Delete(marker);
                var f = new NativeFault { Fault = fault };
                string script = "[IO.File]::WriteAllText('" + marker.Replace("'", "''") + "','started'); Start-Sleep -Seconds 2";
                int result = OuterBrowserSupervisor.RunCore(pwsh, new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)) }, f);
                if (fault == "success")
                    Require(result == 0 && f.Resumes == 1 && File.Exists(marker), "native success");
                else {
                    Require(result == 1 && f.Assignments == 1, "native failure");
                    if (fault == "assignment" || fault == "membership")
                        Require(f.Resumes == 0 && !File.Exists(marker), "suspended rollback");
                    if (fault == "assignment") Require(f.Rollbacks == 1 && f.Waits == 1 && f.RollbackWait == 0, "original handle rollback");
                    if (fault == "membership-running" || fault == "membership-unknown")
                        Require(f.Resumes == 1 && f.Members >= 2 && f.AbortConfirmed, "running membership failure");
                    if (fault == "counter" || fault == "zero-counter") Require(f.Resumes == 1 && f.Memories > 0, "counter failure");
                    if (fault == "accounting") Require(f.Resumes == 1 && f.Accounts > 0, "accounting failure");
                    if (fault == "enumeration") Require(f.Resumes == 1 && f.Enumerations >= 2, "enumeration failure");
                }
            }
            if (File.Exists(marker)) File.Delete(marker);
        }
        public static void InnerCompatibility(string pwsh, string fixture, string profile, string marker) {
            var f = new NativeFault { Fault = "success" };
            int result = OuterBrowserSupervisor.RunCore(pwsh, new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", fixture, "-Owner", "-FixtureProfile", profile, "-Marker", marker }, f);
            Require(result == 0 && f.MaxActive >= 2 && File.Exists(marker), "nested browser owner compatibility");
            File.Delete(marker);
        }
        public static void Watchdog(string pwsh, string marker) {
            var f = new NativeFault { Fault = "watchdog", DeadlineMarker = marker };
            string script = "[IO.File]::WriteAllText('" + marker.Replace("'", "''") + "','started'); Start-Sleep -Seconds 30";
            int result = OuterBrowserSupervisor.RunCore(pwsh, new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)) }, f);
            Require(result == 1 && f.DeadlineReleased && f.Resumes == 1 && f.AbortConfirmed && f.RollbackWait == 0, "native watchdog termination");
            if (File.Exists(marker)) File.Delete(marker);
        }
        public static void ChildSurvival(string pwsh, string marker) {
            var f = new NativeFault { Fault = "success" };
            string path = marker.Replace("'", "''");
            string child = "[IO.File]::WriteAllText('" + path + "',[string]$PID); Start-Sleep -Seconds 30";
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(child));
            string root = "Start-Sleep -Seconds 2; Start-Process -FilePath '" + pwsh.Replace("'", "''") +
                "' -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','" + encoded +
                "'); while (-not [IO.File]::Exists('" + path + "')) { Start-Sleep -Milliseconds 20 }; Start-Sleep -Seconds 2";
            var observer = Task.Run(() => {
                var clock = Stopwatch.StartNew();
                while (clock.ElapsedMilliseconds < 12000) {
                    if (File.Exists(marker)) {
                        int pid;
                        if (Int32.TryParse(File.ReadAllText(marker), out pid) && pid > 0) {
                            var handle = new KernelHandle(LaunchBound.Native.OpenProcess(0x100000, false, pid));
                            if (!handle.IsInvalid) return handle;
                            handle.Dispose();
                        }
                    }
                    Thread.Sleep(10);
                }
                return null;
            });
            var report = new OuterResult();
            int result = OuterBrowserSupervisor.RunCore(pwsh, new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(root)) }, f, report);
            Require(observer.Wait(12000), "child observer timeout");
            using (var childHandle = observer.Result) {
                Require(result == 1 && f.MaxActive >= 2 && f.RootExitObserved && f.AbortConfirmed && childHandle != null &&
                    LaunchBound.Native.WaitForSingleObject(childHandle, 5000) == 0,
                    "surviving child cleanup: phase=" + report.FailurePhase + ", step=" + report.FailureStep +
                    ", kind=" + report.FailureKind + ", maxActive=" + f.MaxActive + ", rootExit=" + f.RootExitObserved +
                    ", abortConfirmed=" + f.AbortConfirmed + ", observer=" + (childHandle != null));
            }
            if (File.Exists(marker)) File.Delete(marker);
        }
    }
}
