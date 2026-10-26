// One launch, one exclusive job. This owner must itself remain in the outer supervisor.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace LaunchBound {
    public sealed class ActorIdentity {
        public int Pid,ParentPid;
        public string CreationFileTime,ImagePath;
        internal static ActorIdentity Read(IntPtr process) {
            uint pid=Native.GetProcessId(process);Native.Check(pid!=0);
            long created,exited,kernel,user;Native.Check(Native.GetProcessTimes(process,out created,out exited,out kernel,out user));
            var image=new StringBuilder(32768);uint length=(uint)image.Capacity;Native.Check(Native.QueryFullProcessImageNameW(process,0,image,ref length));
            Native.ProcessBasic info;int returned;int status=Native.NtQueryInformationProcess(process,0,out info,Marshal.SizeOf<Native.ProcessBasic>(),out returned);
            if(status!=0 || returned!=Marshal.SizeOf<Native.ProcessBasic>() || info.pid.ToInt64()!=pid || created<=0 || info.parent.ToInt64()<=0)throw new InvalidOperationException("Actor parent identity unavailable.");
            return new ActorIdentity{Pid=checked((int)pid),ParentPid=checked((int)info.parent.ToInt64()),CreationFileTime=created.ToString(System.Globalization.CultureInfo.InvariantCulture),ImagePath=image.ToString()};
        }
        internal static bool Same(ActorIdentity expected,ActorIdentity actual) {
            return expected!=null && actual!=null && expected.Pid>0 && expected.ParentPid>0 && expected.Pid==actual.Pid && expected.ParentPid==actual.ParentPid && expected.CreationFileTime==actual.CreationFileTime && String.Equals(expected.ImagePath,actual.ImagePath,StringComparison.OrdinalIgnoreCase);
        }
    }
    public sealed class Snapshot {
        public string RunId, ProfileKey;
        public bool Created, Assigned, Resumed, Sealed, Terminal, Confirmed, Forced, StreamsComplete, RootInOuterBeforeInner, OuterPolicyConfirmed;
        public long OuterJobLimitBytes;
        public long WorkingSetBytes, PrivateBytes;
        public int ActiveProcesses;
        public int[] Pids = Array.Empty<int>();
        public int? ExitCode;
    }
    public sealed class StreamData { public long Bytes; public string Text = ""; public bool Truncated, Eof, Failed; }
    public sealed class CaptureData {
        public bool Started, TimedOut, DrainIncomplete;
        public int? ExitCode;
        public StreamData Stdout = new StreamData(), Stderr = new StreamData();
        public Snapshot Completion;
    }
    internal sealed class FailureDiagnostic {
        public Snapshot Setup;
        public bool RollbackContained,StdoutCompleted,StderrCompleted,DrainJoinCompleted;
        public long DrainJoinElapsedMilliseconds;
        public int RootPid;
        public uint? RetainedRootWaitResult;
        public int? RetainedRootExitCode,NativeErrorCode;
        public StreamData Stdout,Stderr;
    }
    internal sealed class KernelHandle : SafeHandleZeroOrMinusOneIsInvalid {
        internal KernelHandle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() { return Native.CloseHandle(handle); }
    }
    internal static class Native {
        [StructLayout(LayoutKind.Sequential)] internal struct ProcessBasic {public IntPtr reserved1,peb,reserved2,reserved3,pid,parent;}
        [DllImport("ntdll.dll")] internal static extern int NtQueryInformationProcess(IntPtr process,int kind,out ProcessBasic value,int size,out int returned);
        [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder image,ref uint size);
        [StructLayout(LayoutKind.Sequential)] internal struct SA { public int size; public IntPtr descriptor; [MarshalAs(UnmanagedType.Bool)] public bool inherit; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] internal struct SI {
            public int cb; public string reserved, desktop, title;
            public uint x,y,xsize,ysize,xchars,ychars,fill,flags;
            public ushort show,reservedSize; public IntPtr reservedBytes,input,output,error;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct SIX { public SI startup; public IntPtr attributes; }
        [StructLayout(LayoutKind.Sequential)] internal struct PI { public IntPtr process,thread; public uint pid,tid; }
        [StructLayout(LayoutKind.Sequential)] internal struct BasicLimit {
            public long perProcess, perJob; public uint flags; public UIntPtr min,max; public uint active;
            public UIntPtr affinity; public uint priority,scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct IO { public ulong r,w,o,rb,wb,ob; }
        [StructLayout(LayoutKind.Sequential)] internal struct Extended { public BasicLimit basic; public IO io; public UIntPtr process,job,peakProcess,peakJob; }
        [StructLayout(LayoutKind.Sequential)] internal struct Accounting { public long user,kernel,periodUser,periodKernel; public uint faults,total,active,terminated; }
        [StructLayout(LayoutKind.Sequential)] internal struct Memory { public uint size,faults; public UIntPtr peakWs,ws,peakPaged,paged,peakNon,non,page,peakPage,privateBytes; }
        [StructLayout(LayoutKind.Sequential)] internal struct SystemMemory { public uint length,load; public ulong total,available,page,availablePage,virtualTotal,availableVirtual,extended; }
        [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr CreateJobObjectW(IntPtr a,string name);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool SetInformationJobObject(KernelHandle h,int kind,ref Extended value,int size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool QueryInformationJobObject(KernelHandle h,int kind,IntPtr value,int size,IntPtr returned);
        [DllImport("kernel32.dll", EntryPoint="QueryInformationJobObject", SetLastError=true)] internal static extern bool QueryCurrentJob(IntPtr h,int kind,IntPtr value,int size,IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool AssignProcessToJobObject(KernelHandle job,KernelHandle process);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool TerminateJobObject(KernelHandle job,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool TerminateProcess(KernelHandle process,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint WaitForSingleObject(KernelHandle handle,uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetExitCodeProcess(KernelHandle process,out uint code);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint ResumeThread(KernelHandle thread);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SA sa,int size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool SetHandleInformation(IntPtr h,uint mask,uint flags);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetHandleInformation(IntPtr h,out uint flags);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool PeekNamedPipe(SafeFileHandle h,IntPtr buffer,uint size,IntPtr read,out uint available,IntPtr left);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool ReadFile(SafeFileHandle h,byte[] buffer,uint size,out uint read,IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr CreateFileW(string name,uint access,uint share,ref SA sa,uint disposition,uint flags,IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref UIntPtr size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,UIntPtr attribute,IntPtr value,UIntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string cwd,ref SIX startup,out PI process);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool K32GetProcessMemoryInfo(KernelHandle process,ref Memory value,uint size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GlobalMemoryStatusEx(ref SystemMemory memory);
        internal static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    // Internal fault seam: production always uses this exact implementation. Test code compiled
    // in the same assembly can exercise rollback without exposing faults over IPC.
    internal class NativeCalls {
        internal virtual bool Assign(KernelHandle job,KernelHandle process) { return Native.AssignProcessToJobObject(job,process); }
        internal virtual uint Resume(KernelHandle thread) { return Native.ResumeThread(thread); }
        internal virtual bool TerminateUnassigned(KernelHandle process) { return Native.TerminateProcess(process,125); }
        internal virtual uint WaitUnassigned(KernelHandle process) { return Native.WaitForSingleObject(process,5000); }
        internal virtual void BeforeQuery() { }
        internal virtual void Counters(ref long ws,ref long privateBytes) { }
        internal virtual int InitialPidCapacity { get { return 32; } }
        internal virtual void PidCapacityAttempt(int capacity) { }
        internal virtual IntPtr OpenQueryProcess(int pid) { return Native.OpenProcess(0x410,false,pid); }
        internal virtual bool Memory(KernelHandle process,ref Native.Memory value) { return Native.K32GetProcessMemoryInfo(process,ref value,value.size); }
        internal virtual void ErrorCaptured() { }
        internal virtual bool RootInOuter(KernelHandle process) { bool member; Native.Check(Native.IsProcessInJob(process.DangerousGetHandle(),IntPtr.Zero,out member)); return member; }
    }
    public sealed class JobOwner : IDisposable {
        readonly object sync = new object();
        readonly NativeCalls calls;
        readonly string runId, profileKey;
        KernelHandle job,root,thread;
        Task<StreamData> stdout,stderr;
        bool attempted,created,assigned,resumed,sealedAssignment,failed,disposed,forced;
        int cancelStreams;
        bool rollbackContained;
        bool rootInOuter,outerPolicyConfirmed;
        long outerLimit;
        int rootPid;
        bool diagnosticDrainJoined;
        FailureDiagnostic failureDiagnostic;
        public JobOwner(string runId,string profile) : this(runId,profile,new NativeCalls()) { }
        internal JobOwner(string id,string profile,NativeCalls native) {
            if (!Guid.TryParseExact(id,"N",out _)) throw new ArgumentException("Invalid run identity.");
            if (!Path.IsPathFullyQualified(profile)) throw new ArgumentException("Invalid profile.");
            runId=id; profileKey=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(profile).TrimEnd('\\').ToUpperInvariant()))).ToLowerInvariant(); calls=native;
        }
        public string RunId { get { return runId; } }
        public static ActorIdentity ReadActorIdentity() {if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();return ActorIdentity.Read(Native.GetCurrentProcess());}
        public string ProfileKey { get { return profileKey; } }
        public bool RollbackContained { get { lock(sync) { return rollbackContained; } } }
        public Snapshot Setup { get { lock(sync) { return new Snapshot{RunId=runId,ProfileKey=profileKey,Created=created,Assigned=assigned,Resumed=resumed,Sealed=sealedAssignment,RootInOuterBeforeInner=rootInOuter,OuterPolicyConfirmed=outerPolicyConfirmed,OuterJobLimitBytes=outerLimit,ActiveProcesses=-1}; } } }
        internal static void ValidateProfileArguments(string[] arguments,string profile) {
            int count=0;
            foreach(string argument in arguments) {
                if(argument==null || argument.IndexOf('\0')>=0) throw new ArgumentException("Ambiguous arguments.");
                // Chromium trims Unicode whitespace before recognizing Windows switch prefixes/keys.
                // Normalize only for override detection; the owned profile must retain its exact canonical form.
                string token=argument.Trim();
                if(token=="--") throw new ArgumentException("Ambiguous arguments.");
                string key=argument.Split('=')[0].TrimStart('-','/');
                int prefix=token.StartsWith("--",StringComparison.Ordinal)?2:(token.StartsWith("-",StringComparison.Ordinal)||token.StartsWith("/",StringComparison.Ordinal)?1:0);
                if(prefix!=0) {
                    string normalizedKey=token.Substring(prefix).Split('=')[0];
                    if(normalizedKey.Equals("user-data-dir",StringComparison.OrdinalIgnoreCase)) key="user-data-dir";
                }
                if(!key.Equals("user-data-dir",StringComparison.OrdinalIgnoreCase)) continue;
                if(!argument.StartsWith("--user-data-dir=",StringComparison.Ordinal) || !String.Equals(argument,token,StringComparison.Ordinal) || ++count!=1) throw new ArgumentException("Ambiguous profile.");
                string value=argument.Substring(16);
                if(!Path.IsPathFullyQualified(value) || !String.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(value)),Path.TrimEndingDirectorySeparator(Path.GetFullPath(profile)),StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Wrong profile.");
            }
            if(count!=1) throw new ArgumentException("Missing profile.");
        }
        internal static long ValidateOuterPolicy(uint flags,ulong bytes,uint ui) {
            if(flags!=0x2200 || ui!=0 || (bytes!=2UL*1024*1024*1024 && bytes!=3UL*1024*1024*1024)) throw new InvalidOperationException("Unsupported outer supervision policy.");
            return checked((long)bytes);
        }
        static T CurrentJob<T>(int kind) where T:struct {
            int size=Marshal.SizeOf<T>(); IntPtr p=Marshal.AllocHGlobal(size);
            try { Native.Check(Native.QueryCurrentJob(IntPtr.Zero,kind,p,size,IntPtr.Zero)); return Marshal.PtrToStructure<T>(p); }
            finally { Marshal.FreeHGlobal(p); }
        }
        internal bool DiagnosticMember(IntPtr retainedProcess) { bool member; Native.Check(Native.IsProcessInJob(retainedProcess,job.DangerousGetHandle(),out member)); return member; }
        public static string Quote(string value) {
            if (value==null || value.IndexOf('\0')>=0) throw new ArgumentException("Invalid argument.");
            var b=new StringBuilder("\""); int slashes=0;
            foreach (char c in value) {
                if (c=='\\') { slashes++; continue; }
                if (c=='"') b.Append('\\',slashes*2+1).Append(c); else b.Append('\\',slashes).Append(c);
                slashes=0;
            }
            return b.Append('\\',slashes*2).Append('"').ToString();
        }
        static Task<StreamData> Drain(SafeFileHandle stream,int limit,Func<bool> cancelled) { return Task.Run(() => {
            var result=new StreamData(); var retained=new MemoryStream(); var buffer=new byte[8192]; var idle=new SpinWait(); var quiet=Stopwatch.StartNew();
            try {
                while (!cancelled()) {
                    uint available,n;
                    if(!Native.PeekNamedPipe(stream,IntPtr.Zero,0,IntPtr.Zero,out available,IntPtr.Zero)) {
                        if(Marshal.GetLastWin32Error()==109) { result.Eof=true; break; } Native.Check(false);
                    }
                    // Keep yielding without timed sleeps during a short writer refill.
                    // Default SpinOnce can sleep after its threshold and throttle small
                    // anonymous pipes. Sustained idle streams retain the default backoff.
                    if(available==0) { if(quiet.ElapsedMilliseconds<10)idle.SpinOnce(-1);else idle.SpinOnce(); continue; }
                    Native.Check(Native.ReadFile(stream,buffer,Math.Min(available,(uint)buffer.Length),out n,IntPtr.Zero));
                    if(n==0) { result.Eof=true; break; }
                    idle.Reset();quiet.Restart();
                    result.Bytes=checked(result.Bytes+n); int keep=Math.Min(checked((int)n),limit-(int)retained.Length);
                    if (keep>0) retained.Write(buffer,0,keep);
                }
                if(!result.Eof) result.Failed=true;
            } catch { result.Failed=true; }
            finally { stream.Dispose(); result.Text=Encoding.UTF8.GetString(retained.ToArray()); retained.Dispose(); }
            result.Truncated=result.Bytes>limit; return result;
        }); }
        static SafeFileHandle ReadPipe(ref Native.SA sa,out KernelHandle childWrite) {
            IntPtr read,write; Native.Check(Native.CreatePipe(out read,out write,ref sa,0));
            childWrite=new KernelHandle(write); var retained=new SafeFileHandle(read,true);
            try { Native.Check(Native.SetHandleInformation(read,1,0)); return retained; }
            catch { retained.Dispose(); childWrite.Dispose(); throw; }
        }
        T QueryStruct<T>(int kind) where T:struct {
            int size=Marshal.SizeOf<T>(); IntPtr p=Marshal.AllocHGlobal(size);
            try { Native.Check(Native.QueryInformationJobObject(job,kind,p,size,IntPtr.Zero)); return Marshal.PtrToStructure<T>(p); }
            finally { Marshal.FreeHGlobal(p); }
        }
        int[] Pids() {
            for (int capacity=calls.InitialPidCapacity;capacity<=32768;capacity*=2) {
                if(capacity<1) throw new InvalidOperationException("Invalid PID capacity."); calls.PidCapacityAttempt(capacity);
                int size=checked(8+IntPtr.Size*capacity); IntPtr p=Marshal.AllocHGlobal(size);
                try {
                    if (!Native.QueryInformationJobObject(job,3,p,size,IntPtr.Zero)) {
                        int error=Marshal.GetLastWin32Error(); if (error==234) continue; throw new Win32Exception(error);
                    }
                    int assignedCount=Marshal.ReadInt32(p),count=Marshal.ReadInt32(p,4);
                    if (count<0 || count>capacity || assignedCount!=count) continue;
                    var ids=new int[count]; for(int i=0;i<count;i++) ids[i]=checked((int)Marshal.ReadIntPtr(p,8+i*IntPtr.Size).ToInt64());
                    Array.Sort(ids); return ids;
                } finally { Marshal.FreeHGlobal(p); }
            }
            throw new InvalidOperationException("Incomplete job membership.");
        }
        public Snapshot Start(string executable,string[] arguments,string profile) {
            lock(sync) {
                if (disposed || attempted) throw new InvalidOperationException("Launch already sealed."); attempted=true;
                var startClock=Stopwatch.StartNew();
                SafeFileHandle outRead=null,errRead=null; KernelHandle outWrite=null,errWrite=null,input=null;
                IntPtr attributes=IntPtr.Zero,handles=IntPtr.Zero; bool attributesReady=false;
                try {
                    if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(executable) || !File.Exists(executable) || arguments==null || arguments.Length>128) throw new ArgumentException("Invalid launch.");
                    if (new JobOwner(runId,profile).ProfileKey!=profileKey) throw new ArgumentException("Wrong profile.");
                    ValidateProfileArguments(arguments,profile);
                    bool inOuter; Native.Check(Native.IsProcessInJob(Native.GetCurrentProcess(),IntPtr.Zero,out inOuter)); if(!inOuter) throw new InvalidOperationException("Outer supervision required.");
                    var outer=CurrentJob<Native.Extended>(9); outerLimit=ValidateOuterPolicy(outer.basic.flags,outer.job.ToUInt64(),CurrentJob<uint>(4));outerPolicyConfirmed=true;
                    job=new KernelHandle(Native.CreateJobObjectW(IntPtr.Zero,null)); Native.Check(!job.IsInvalid);
                    uint inheritedFlags; Native.Check(Native.GetHandleInformation(job.DangerousGetHandle(),out inheritedFlags)); if((inheritedFlags&1)!=0) throw new InvalidOperationException("Inheritable job handle.");
                    var limits=new Native.Extended(); limits.basic.flags=0x2000; Native.Check(Native.SetInformationJobObject(job,9,ref limits,Marshal.SizeOf<Native.Extended>()));
                    var checkedLimits=QueryStruct<Native.Extended>(9); if(checkedLimits.basic.flags!=0x2000 || QueryStruct<uint>(4)!=0) throw new InvalidOperationException("Unexpected job limits.");
                    bool ownerMember; Native.Check(Native.IsProcessInJob(Native.GetCurrentProcess(),job.DangerousGetHandle(),out ownerMember)); if(ownerMember) throw new InvalidOperationException("Owner inside browser job.");
                    var sa=new Native.SA{size=Marshal.SizeOf<Native.SA>(),inherit=true};
                    outRead=ReadPipe(ref sa,out outWrite); errRead=ReadPipe(ref sa,out errWrite);
                    input=new KernelHandle(Native.CreateFileW("NUL",0x80000000,3,ref sa,3,0,IntPtr.Zero)); Native.Check(!input.IsInvalid);
                    UIntPtr bytes=UIntPtr.Zero; Native.InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
                    attributes=Marshal.AllocHGlobal(checked((int)bytes.ToUInt64())); Native.Check(Native.InitializeProcThreadAttributeList(attributes,1,0,ref bytes)); attributesReady=true;
                    handles=Marshal.AllocHGlobal(3*IntPtr.Size); Marshal.WriteIntPtr(handles,0,input.DangerousGetHandle()); Marshal.WriteIntPtr(handles,IntPtr.Size,outWrite.DangerousGetHandle()); Marshal.WriteIntPtr(handles,2*IntPtr.Size,errWrite.DangerousGetHandle());
                    Native.Check(Native.UpdateProcThreadAttribute(attributes,0,new UIntPtr(0x20002),handles,new UIntPtr((uint)(3*IntPtr.Size)),IntPtr.Zero,IntPtr.Zero));
                    var si=new Native.SIX{startup=new Native.SI{cb=Marshal.SizeOf<Native.SIX>(),flags=0x100,input=input.DangerousGetHandle(),output=outWrite.DangerousGetHandle(),error=errWrite.DangerousGetHandle()},attributes=attributes};
                    string command=Quote(executable)+" "+String.Join(" ",arguments.Select(Quote)); if(command.Length>=32767) throw new ArgumentException("Command too long.");
                    Native.PI pi; Native.Check(Native.CreateProcessW(executable,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,true,0x08080004,IntPtr.Zero,Path.GetDirectoryName(executable),ref si,out pi));
                    root=new KernelHandle(pi.process); thread=new KernelHandle(pi.thread); rootPid=checked((int)pi.pid);created=true;
                    rootInOuter=calls.RootInOuter(root); if(!rootInOuter) throw new InvalidOperationException("Suspended root outside outer supervision.");
                    // Parent copies must close before readers can observe EOF.
                    outWrite.Dispose(); outWrite=null; errWrite.Dispose(); errWrite=null; input.Dispose(); input=null;
                    Native.Check(calls.Assign(job,root)); assigned=true;
                    bool member; Native.Check(Native.IsProcessInJob(root.DangerousGetHandle(),job.DangerousGetHandle(),out member));
                    if(!member || !Pids().Contains(checked((int)pi.pid)) || QueryStruct<Native.Accounting>(1).total<1) throw new InvalidOperationException("Assignment unproved.");
                    sealedAssignment=true;
                    stdout=Drain(outRead,64*1024*1024,()=>Volatile.Read(ref cancelStreams)!=0); outRead=null; stderr=Drain(errRead,64*1024,()=>Volatile.Read(ref cancelStreams)!=0); errRead=null;
                    if(startClock.ElapsedMilliseconds>=15000) throw new TimeoutException("Late launch setup.");
                    if(calls.Resume(thread)!=1) throw new InvalidOperationException("Unexpected resume state."); resumed=true;
                    var started=Query(5000); if(startClock.ElapsedMilliseconds>=15000) throw new TimeoutException("Late launch result."); return started;
                } catch {
                    failed=true;
                    ContainFailure();
                    throw;
                } finally {
                    outWrite?.Dispose(); errWrite?.Dispose(); input?.Dispose(); outRead?.Dispose(); errRead?.Dispose();
                    if(attributesReady) Native.DeleteProcThreadAttributeList(attributes); if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes); if(handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);
                }
            }
        }
        public Snapshot Query(int milliseconds) {
            lock(sync) {
                if(disposed || !resumed || !sealedAssignment || failed) throw new InvalidOperationException("Owner state unknown.");
                var clock=Stopwatch.StartNew();
                try {
                    do {
                        calls.BeforeQuery(); uint before=QueryStruct<Native.Accounting>(1).active; int[] ids=Pids(); long ws=0,privateBytes=0; bool changed=false;
                        foreach(int pid in ids) {
                            IntPtr raw=calls.OpenQueryProcess(pid);int openError=Marshal.GetLastWin32Error();
                            using(var process=new KernelHandle(raw)) {
                                if(process.IsInvalid) { calls.ErrorCaptured(); if(!Pids().Contains(pid)) { changed=true; break; } throw new Win32Exception(openError); }
                                bool member; Native.Check(Native.IsProcessInJob(process.DangerousGetHandle(),job.DangerousGetHandle(),out member));
                                if(!member) { if(!Pids().Contains(pid)) { changed=true; break; } throw new InvalidOperationException("Membership unproved."); }
                                var m=new Native.Memory{size=(uint)Marshal.SizeOf<Native.Memory>()};
                                if(!calls.Memory(process,ref m)) { int error=Marshal.GetLastWin32Error(); calls.ErrorCaptured(); if(!Pids().Contains(pid)) { changed=true; break; } throw new Win32Exception(error); }
                                long w=checked((long)m.ws.ToUInt64()),p=checked((long)m.privateBytes.ToUInt64()); calls.Counters(ref w,ref p); if(w<0||p<0) throw new InvalidOperationException("Invalid memory.");
                                ws=checked(ws+w); privateBytes=checked(privateBytes+p);
                            }
                        }
                        int[] afterIds=Pids(); uint after=QueryStruct<Native.Accounting>(1).active;
                        if(changed || before!=after || before!=ids.Length || !ids.SequenceEqual(afterIds)) { Thread.Sleep(10); continue; }
                        bool streams=stdout!=null && stderr!=null && stdout.IsCompleted && stderr.IsCompleted && stdout.Result.Eof && stderr.Result.Eof && !stdout.Result.Failed && !stderr.Result.Failed;
                        if((stdout?.IsCompleted==true && stdout.Result.Failed)||(stderr?.IsCompleted==true && stderr.Result.Failed)) throw new IOException("Stream failed.");
                        uint exit; int? exitCode=null; if(Native.WaitForSingleObject(root,0)==0) { Native.Check(Native.GetExitCodeProcess(root,out exit)); exitCode=unchecked((int)exit); }
                        if(clock.ElapsedMilliseconds>=milliseconds) throw new TimeoutException("Late job query.");
                        return new Snapshot{RunId=runId,ProfileKey=profileKey,Created=created,Assigned=assigned,Resumed=resumed,Sealed=sealedAssignment,RootInOuterBeforeInner=rootInOuter,OuterPolicyConfirmed=outerPolicyConfirmed,OuterJobLimitBytes=outerLimit,Terminal=before==0&&ids.Length==0&&after==0,Confirmed=before==0&&ids.Length==0&&after==0&&streams,Forced=forced,StreamsComplete=streams,ActiveProcesses=checked((int)after),Pids=ids,WorkingSetBytes=ws,PrivateBytes=privateBytes,ExitCode=exitCode};
                    } while(clock.ElapsedMilliseconds<milliseconds);
                    throw new TimeoutException("Job query exceeded budget.");
                } catch { failed=true; throw; }
            }
        }
        public Snapshot Stop(int milliseconds) {
            lock(sync) {
                if(disposed || job==null || !assigned) throw new InvalidOperationException("Owner state unknown.");
                var clock=Stopwatch.StartNew();
                try {
                    // Always contain even when an earlier query made confirmation impossible.
                    if(QueryStruct<Native.Accounting>(1).active!=0) { Native.Check(Native.TerminateJobObject(job,125)); forced=true; }
                    do { var result=Query(Math.Max(1,milliseconds-(int)clock.ElapsedMilliseconds)); if(clock.ElapsedMilliseconds>=milliseconds) throw new TimeoutException("Late completion."); if(result.Confirmed) return result; Thread.Sleep(10); } while(clock.ElapsedMilliseconds<milliseconds);
                    throw new TimeoutException("Completion exceeded budget.");
                } catch { failed=true; throw; }
            }
        }
        public bool Contains(int pid) {
            lock(sync) {
                if(disposed || failed || job==null || pid<=0) throw new InvalidOperationException("Membership unknown.");
                using(var process=new KernelHandle(Native.OpenProcess(0x1000,false,pid))) {
                    Native.Check(!process.IsInvalid); bool member; Native.Check(Native.IsProcessInJob(process.DangerousGetHandle(),job.DangerousGetHandle(),out member)); return member;
                }
            }
        }
        public CaptureData RunCaptured(string executable,string[] arguments,string profile,int milliseconds) {
            Start(executable,arguments,profile); uint wait=Native.WaitForSingleObject(root,checked((uint)milliseconds));
            if(wait==0xffffffff) { failed=true; Native.Check(false); } bool timeout=wait!=0;
            var completion=Stop(5000);
            return new CaptureData{Started=true,TimedOut=timeout,DrainIncomplete=!completion.StreamsComplete,ExitCode=completion.ExitCode,Stdout=stdout.Result,Stderr=stderr.Result,Completion=completion};
        }
        internal static StreamData DiagnosticPrefix(StreamData value) {
            if(value==null)return new StreamData{Failed=true};
            int length=Math.Min(value.Text.Length,8192);
            return new StreamData{Bytes=value.Bytes,Text=value.Text.Substring(0,length),Truncated=value.Truncated||length<value.Text.Length,Eof=value.Eof,Failed=value.Failed};
        }
        internal FailureDiagnostic ReadFailureDiagnostic() {
            lock(sync) {
                if(!failed || disposed)throw new InvalidOperationException("No retained failed launch.");
                if(failureDiagnostic!=null)return failureDiagnostic;
                // Containment already ran in Start's catch. Reuse the existing one-second disposal
                // drain join here, before the tasks and original process handle can be discarded.
                var clock=Stopwatch.StartNew();bool joined=false;
                try {joined=Task.WhenAll(stdout??Task.FromResult(new StreamData()),stderr??Task.FromResult(new StreamData())).Wait(1000);}catch{}
                diagnosticDrainJoined=true;
                var result=new FailureDiagnostic{Setup=Setup,RollbackContained=rollbackContained,RootPid=rootPid,DrainJoinCompleted=joined,DrainJoinElapsedMilliseconds=clock.ElapsedMilliseconds,StdoutCompleted=stdout?.IsCompletedSuccessfully==true,StderrCompleted=stderr?.IsCompletedSuccessfully==true};
                result.Stdout=DiagnosticPrefix(result.StdoutCompleted?stdout.Result:null);result.Stderr=DiagnosticPrefix(result.StderrCompleted?stderr.Result:null);
                if(root!=null && !root.IsInvalid && !root.IsClosed) {
                    uint wait=Native.WaitForSingleObject(root,0);int error=Marshal.GetLastWin32Error();result.RetainedRootWaitResult=wait;
                    if(wait==0) {uint code;if(Native.GetExitCodeProcess(root,out code))result.RetainedRootExitCode=unchecked((int)code);else result.NativeErrorCode=Marshal.GetLastWin32Error();}
                    else if(wait==0xffffffff)result.NativeErrorCode=error;
                }
                failureDiagnostic=result;return result;
            }
        }
        void ContainFailure() {
            if(rollbackContained) return;
            rollbackContained=false;
            try {
                if(assigned && job!=null) {
                    var clock=Stopwatch.StartNew(); Native.Check(Native.TerminateJobObject(job,125));
                    do {
                        var before=QueryStruct<Native.Accounting>(1).active; var ids=Pids(); var after=QueryStruct<Native.Accounting>(1).active;
                        if(clock.ElapsedMilliseconds>=5000) break;
                        if(before==0 && ids.Length==0 && after==0) { rollbackContained=true; break; } Thread.Sleep(10);
                    } while(clock.ElapsedMilliseconds<5000);
                } else if(created && root!=null) {
                    var clock=Stopwatch.StartNew();
                    bool terminated=calls.TerminateUnassigned(root); uint waited=calls.WaitUnassigned(root);
                    rollbackContained=terminated && waited==0 && clock.ElapsedMilliseconds<5000;
                }
            } catch { rollbackContained=false; }
        }
        public void Dispose() {
            lock(sync) {
                if(disposed) return; disposed=true;
                Volatile.Write(ref cancelStreams,1);
                // Owner loss is containment only. No receipt can be queried after this close.
                ContainFailure();
                job?.Dispose();
                thread?.Dispose(); root?.Dispose();
                if(!diagnosticDrainJoined)try { Task.WhenAll(stdout??Task.FromResult(new StreamData()),stderr??Task.FromResult(new StreamData())).Wait(1000); } catch { }
            }
        }
    }
}
