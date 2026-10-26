// Explicit native controls only. No faults or test capacity can be selected over production IPC.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Text.Json;
using LaunchBoundTests;
namespace LaunchBound {
    public static class NativeControls {
        sealed class FirstCensus : NativeCalls {
            readonly string directory; bool waited;
            internal FirstCensus(string dir) { directory=dir; }
            internal override void BeforeQuery() { if(!waited) { waited=true; WaitFile(directory,"grandchild.json"); WaitFile(directory,"root-done"); Thread.Sleep(100); } }
        }
        sealed class AssignmentFailure : NativeCalls {
            internal int Terminations,Waits;
            internal override bool Assign(KernelHandle job,KernelHandle process) { Marshal.SetLastPInvokeError(5); return false; }
            internal override bool TerminateUnassigned(KernelHandle process) { Terminations++; return Terminations==1?false:base.TerminateUnassigned(process); }
            internal override uint WaitUnassigned(KernelHandle process) { Waits++; return Waits==1?258:base.WaitUnassigned(process); }
        }
        sealed class MissingOuter : NativeCalls { internal override bool RootInOuter(KernelHandle process) { return false; } }
        sealed class SmallCapacity : NativeCalls {
            internal readonly List<int> Attempts=new List<int>();
            internal override int InitialPidCapacity { get { return 2; } }
            internal override void PidCapacityAttempt(int capacity) { Attempts.Add(capacity); }
        }
        sealed class QueryFault : NativeCalls {
            internal bool Bad,Delay,Negative,OpenError,MemoryError;
            internal override void BeforeQuery() { if(Delay) Thread.Sleep(30); if(Bad) throw new InvalidOperationException("Synthetic query fault."); }
            internal override void Counters(ref long ws,ref long privateBytes) { if(Negative) privateBytes=-1; }
            internal override IntPtr OpenQueryProcess(int pid) { if(OpenError) { Marshal.SetLastPInvokeError(5); return IntPtr.Zero; } return base.OpenQueryProcess(pid); }
            internal override bool Memory(KernelHandle process,ref Native.Memory value) { if(MemoryError) { Marshal.SetLastPInvokeError(5); return false; } return base.Memory(process,ref value); }
            internal override void ErrorCaptured() { Marshal.SetLastPInvokeError(0); }
        }
        sealed class Marker { public int Pid,Parent; public string Creation,Image,Run,Mode,Product; }
        // Fixture-only descendant launch. Never selected through the production owner protocol.
        class FixtureChildCalls {
            [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetStdHandle(int which);
            [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
            [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr duplicate,uint access,bool inherit,uint options);
            [DllImport("kernel32.dll",EntryPoint="TerminateProcess",SetLastError=true)] static extern bool TerminateChild(IntPtr process,uint code);
            [DllImport("kernel32.dll",EntryPoint="WaitForSingleObject",SetLastError=true)] static extern uint WaitChild(IntPtr process,uint milliseconds);
            internal virtual bool InJob(IntPtr process) { bool member;Native.Check(Native.IsProcessInJob(process,IntPtr.Zero,out member));return member; }
            internal virtual IntPtr Capture(int which) { return GetStdHandle(which); }
            internal virtual bool Pipe(IntPtr handle) { return GetFileType(handle)==3; }
            internal virtual bool Inheritable(IntPtr handle) { uint flags;Native.Check(Native.GetHandleInformation(handle,out flags));return (flags&1)!=0; }
            internal virtual IntPtr Duplicate(IntPtr original) {
                IntPtr duplicate=IntPtr.Zero;
                try {
                    Native.Check(DuplicateHandle(Native.GetCurrentProcess(),original,Native.GetCurrentProcess(),out duplicate,0,true,2));
                    return duplicate;
                } catch { if(duplicate!=IntPtr.Zero && duplicate!=new IntPtr(-1)) Native.Check(Native.CloseHandle(duplicate));throw; }
            }
            internal virtual IntPtr NullInput() {
                var sa=new Native.SA{size=Marshal.SizeOf<Native.SA>(),inherit=true};
                IntPtr handle=Native.CreateFileW("NUL",0x80000000,3,ref sa,3,0,IntPtr.Zero);
                if(handle==IntPtr.Zero || handle==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return handle;
            }
            internal virtual UIntPtr AttributeSize() { UIntPtr bytes=UIntPtr.Zero;Native.InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);return bytes; }
            internal virtual void Initialize(IntPtr list,ref UIntPtr bytes) { Native.Check(Native.InitializeProcThreadAttributeList(list,1,0,ref bytes)); }
            internal virtual void SetHandles(IntPtr list,IntPtr handles) { Native.Check(Native.UpdateProcThreadAttribute(list,0,new UIntPtr(0x20002),handles,new UIntPtr((uint)(3*IntPtr.Size)),IntPtr.Zero,IntPtr.Zero)); }
            internal virtual void Delete(IntPtr list) { Native.DeleteProcThreadAttributeList(list); }
            internal virtual bool Create(string executable,StringBuilder command,uint flags,bool inherit,ref Native.SIX startup,out Native.PI pi) { return Native.CreateProcessW(executable,command,IntPtr.Zero,IntPtr.Zero,inherit,flags,IntPtr.Zero,Path.GetDirectoryName(executable),ref startup,out pi); }
            internal virtual void Rollback(IntPtr process) { uint wait=WaitChild(process,0);if(wait==0)return;if(wait!=258)throw new Win32Exception(Marshal.GetLastWin32Error());Native.Check(TerminateChild(process,125));if(WaitChild(process,5000)!=0) throw new InvalidOperationException("Fixture child rollback unknown."); }
            [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
            [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder image,ref uint size);
            [DllImport("kernel32.dll",EntryPoint="GetExitCodeProcess",SetLastError=true)] static extern bool ChildExitCode(IntPtr process,out uint code);
            internal virtual void ObserveChild(IntPtr process,uint pid,string directory,string mode,string run,long elapsed) {
                long created,exited,kernel,user;Native.Check(GetProcessTimes(process,out created,out exited,out kernel,out user));
                var image=new StringBuilder(32768);uint size=(uint)image.Capacity;Native.Check(QueryFullProcessImageNameW(process,0,image,ref size));
                bool member=InJob(process);uint wait=WaitChild(process,0);Require(wait==0 || wait==258,"Fixture child observation wait unknown.");
                uint? exit=null;if(wait==0){uint code;Native.Check(ChildExitCode(process,out code));exit=code;}
                Directory.CreateDirectory(Path.Combine(directory,"launch-diagnostics"));
                Write(FixtureDiagnosticPath(directory,"launch-observation-"+pid+".json"),new{Pid=pid,ParentPid=Environment.ProcessId,CreationFileTime=created.ToString(System.Globalization.CultureInfo.InvariantCulture),ImagePath=image.ToString(),InJob=member,WaitResult=wait,ExitCode=exit,Mode=mode,RunId=run,ElapsedMilliseconds=elapsed,Scope="original child handle immediate observation; not later readiness or family completion"});
            }
            internal virtual void Close(IntPtr handle) { Native.Check(Native.CloseHandle(handle)); }
        }
        static string FixtureDiagnosticPath(string directory,string name) { return Path.Combine(directory,"launch-diagnostics",name); }
        static bool ValidHandle(IntPtr handle) { return handle!=IntPtr.Zero && handle!=new IntPtr(-1); }
        static void ChildCleanup(List<Exception> failures,Action action) { try { action(); } catch(Exception error) { failures.Add(error); } }
        static IntPtr DuplicateFixturePipe(FixtureChildCalls calls,int which) {
            IntPtr original=calls.Capture(which),duplicate=IntPtr.Zero;
            Require(ValidHandle(original) && calls.Pipe(original),"Fixture capture pipe unavailable.");
            try { duplicate=calls.Duplicate(original);Require(ValidHandle(duplicate) && duplicate!=original && calls.Inheritable(duplicate) && calls.Pipe(duplicate),"Fixture capture duplicate invalid.");return duplicate; }
            catch { if(ValidHandle(duplicate) && duplicate!=original) calls.Close(duplicate);throw; }
        }
        public static void StartFixtureDescendant(string executable,string[] arguments,string profile) { StartFixtureDescendant(executable,arguments,profile,new FixtureChildCalls()); }
        static void StartFixtureDescendant(string executable,string[] arguments,string profile,FixtureChildCalls calls) {
            Require(OperatingSystem.IsWindows() && Path.IsPathFullyQualified(executable) && File.Exists(executable) && String.Equals(executable,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase),"Fixture executable changed.");
            Require(arguments!=null && arguments.Length==10 && arguments.All(value=>value!=null && value.IndexOf('\0')<0),"Fixture child arguments unavailable.");
            Require(arguments.Take(4).SequenceEqual(new[]{"-NoLogo","-NoProfile","-NonInteractive","-File"}) && Path.IsPathFullyQualified(arguments[4]) && File.Exists(arguments[4]),"Fixture child script changed.");
            Require(new[]{"--mode=child","--mode=grandchild","--mode=hold"}.Contains(arguments[5]) && arguments[6].StartsWith("--directory-b64=",StringComparison.Ordinal) && arguments[8].StartsWith("--fixture-run=",StringComparison.Ordinal) && arguments[8].Length==46 && arguments[8].Substring(14).All(ch=>ch>='0'&&ch<='9'||ch>='a'&&ch<='f') && arguments[9]=="--parent-pid="+Environment.ProcessId,"Fixture child identity changed.");
            string encodedDirectory=arguments[6].Substring(16);byte[] directoryBytes=Convert.FromBase64String(encodedDirectory);string directory=new UTF8Encoding(false,true).GetString(directoryBytes);
            Require(Convert.ToBase64String(directoryBytes)==encodedDirectory && Path.IsPathFullyQualified(directory) && directory.IndexOf('\0')<0,"Fixture child directory changed.");
            JobOwner.ValidateProfileArguments(arguments,profile);
            string command=JobOwner.Quote(executable)+" "+String.Join(" ",arguments.Select(JobOwner.Quote));Require(command.Length<32767,"Fixture child command too long.");
            Require(calls.InJob(Native.GetCurrentProcess()),"Fixture parent outside containment.");
            var launchClock=Stopwatch.StartNew();
            IntPtr output=IntPtr.Zero,error=IntPtr.Zero,input=IntPtr.Zero,list=IntPtr.Zero,handles=IntPtr.Zero;bool initialized=false;Native.PI pi=default;
            var failures=new List<Exception>();
            try {
                output=DuplicateFixturePipe(calls,-11);
                error=DuplicateFixturePipe(calls,-12);
                input=calls.NullInput();Require(ValidHandle(input) && calls.Inheritable(input),"Fixture stdin unavailable.");
                UIntPtr bytes=calls.AttributeSize();Require(bytes.ToUInt64()>0 && bytes.ToUInt64()<=65536,"Fixture attribute capacity invalid.");
                list=Marshal.AllocHGlobal(checked((int)bytes.ToUInt64()));handles=Marshal.AllocHGlobal(3*IntPtr.Size);
                calls.Initialize(list,ref bytes);initialized=true;
                Marshal.WriteIntPtr(handles,input);Marshal.WriteIntPtr(handles,IntPtr.Size,output);Marshal.WriteIntPtr(handles,2*IntPtr.Size,error);calls.SetHandles(list,handles);
                var startup=new Native.SIX{startup=new Native.SI{cb=Marshal.SizeOf<Native.SIX>(),flags=0x100,input=input,output=output,error=error},attributes=list};
                bool created=calls.Create(executable,new StringBuilder(command),0x08080000,true,ref startup,out pi);
                if(!created) throw new Win32Exception(Marshal.GetLastWin32Error());
                Require(ValidHandle(pi.process) && ValidHandle(pi.thread) && calls.InJob(pi.process),"Fixture child containment unavailable.");
                calls.ObserveChild(pi.process,pi.pid,directory,arguments[5].Substring(7),arguments[8].Substring(14),launchClock.ElapsedMilliseconds);
            } catch(Exception failure) { failures.Add(failure); }
            finally {
                // Keep the original process handle until all temporary cleanup has been attempted.
                // Process-only rollback is not certification of family cleanup: existing jobs own descendants.
                if(initialized) ChildCleanup(failures,()=>calls.Delete(list));
                if(list!=IntPtr.Zero) ChildCleanup(failures,()=>Marshal.FreeHGlobal(list));
                if(handles!=IntPtr.Zero) ChildCleanup(failures,()=>Marshal.FreeHGlobal(handles));
                foreach(IntPtr handle in new[]{input,error,output,pi.thread}) if(ValidHandle(handle)) ChildCleanup(failures,()=>calls.Close(handle));
                if(failures.Count>0 && ValidHandle(pi.process)) ChildCleanup(failures,()=>calls.Rollback(pi.process));
                if(ValidHandle(pi.process)) {
                    try { calls.Close(pi.process); }
                    catch(Exception failure) { failures.Add(failure);ChildCleanup(failures,()=>calls.Rollback(pi.process)); }
                }
            }
            if(failures.Count>0) throw new AggregateException("Fixture child launch/cleanup failed; authoritative job cleanup required.",failures);
        }
        sealed class FixtureChildFault : FixtureChildCalls {
            internal string Failure;internal readonly List<string> Events=new List<string>();internal readonly List<IntPtr> Closed=new List<IntPtr>();
            internal string ExpectedCommand;internal bool Created,Deleted,RollbackAttempted;
            internal override bool InJob(IntPtr process) { if(process==new IntPtr(104)){if(Failure=="member-query")throw new InvalidOperationException("Synthetic membership failure.");return Failure!="member-false" && Failure!="rollback";}return Failure!="parent-outside"; }
            internal override IntPtr Capture(int which) { return Failure=="invalid-pipe"?IntPtr.Zero:Failure=="minus-pipe"?new IntPtr(-1):new IntPtr(which==-11?11:12); }
            internal override bool Pipe(IntPtr handle) { return Failure!="nonpipe" && !(Failure=="duplicate-nonpipe" && handle==new IntPtr(101)); }
            internal override bool Inheritable(IntPtr handle) { return !(Failure=="not-inheritable" && handle==new IntPtr(101)) && !(Failure=="nul-not-inheritable" && handle==new IntPtr(103)); }
            internal override IntPtr Duplicate(IntPtr original) { Events.Add("duplicate"+original);if(Failure=="pipe-11" && original==new IntPtr(11) || Failure=="pipe-12" && original==new IntPtr(12))throw new InvalidOperationException("Synthetic capture failure.");if(Failure=="duplicate-alias")return original;return new IntPtr(original==new IntPtr(11)?101:102); }
            internal override IntPtr NullInput() { if(Failure=="nul")throw new InvalidOperationException("Synthetic NUL failure.");return Failure=="nul-invalid"?IntPtr.Zero:new IntPtr(103); }
            internal override UIntPtr AttributeSize() { return new UIntPtr(Failure=="attribute-zero"?0U:Failure=="attribute-capacity"?65537U:256U); }
            internal override void Initialize(IntPtr list,ref UIntPtr bytes) { if(Failure=="initialize")throw new InvalidOperationException("Synthetic attribute failure."); }
            internal override void SetHandles(IntPtr list,IntPtr handles) { Require(Marshal.ReadIntPtr(handles)==new IntPtr(103) && Marshal.ReadIntPtr(handles,IntPtr.Size)==new IntPtr(101) && Marshal.ReadIntPtr(handles,2*IntPtr.Size)==new IntPtr(102),"Inherited handle list changed.");if(Failure=="update")throw new InvalidOperationException("Synthetic update failure."); }
            internal override void Delete(IntPtr list) { Deleted=true;if(Failure=="delete")throw new InvalidOperationException("Synthetic delete failure."); }
            internal override bool Create(string executable,StringBuilder command,uint flags,bool inherit,ref Native.SIX startup,out Native.PI pi) {
                Require(command.ToString()==ExpectedCommand && flags==0x08080000 && inherit && startup.startup.flags==0x100 && startup.startup.cb==Marshal.SizeOf<Native.SIX>() && startup.startup.input==new IntPtr(103) && startup.startup.output==new IntPtr(101) && startup.startup.error==new IntPtr(102) && startup.attributes!=IntPtr.Zero,"Native fixture startup changed.");
                pi=default;if(Failure=="create")return false;pi=new Native.PI{process=Failure=="thread-only"?IntPtr.Zero:new IntPtr(104),thread=Failure=="process-only"?IntPtr.Zero:new IntPtr(105)};Created=true;if(Failure=="partial-create")return false;if(Failure=="create-throw")throw new InvalidOperationException("Synthetic partial creation failure.");return true;
            }
            internal override void ObserveChild(IntPtr process,uint pid,string directory,string mode,string run,long elapsed) {
                Require(process==new IntPtr(104) && !Closed.Contains(process) && directory==@"C:\space path\é😀" && mode=="child" && run==new string('a',32) && elapsed>=0,"Fixture observation identity/order changed.");
                Events.Add("observe");if(Failure=="observe")throw new InvalidOperationException("Synthetic observation failure.");
            }
            internal override void Rollback(IntPtr process) { Require(process==new IntPtr(104) && !Closed.Contains(process),"Rollback lost original process handle.");RollbackAttempted=true;if(Failure=="rollback")throw new InvalidOperationException("Synthetic rollback uncertainty."); }
            internal override void Close(IntPtr handle) { Require(handle.ToInt64()>=101 && handle.ToInt64()<=105 && !Closed.Contains(handle),"Original/duplicate handle closed incorrectly.");if(Failure=="process-close" && handle==new IntPtr(104))throw new InvalidOperationException("Synthetic process close uncertainty.");Closed.Add(handle);if(Failure=="close" && handle==new IntPtr(103))throw new InvalidOperationException("Synthetic close failure."); }
        }
        static void FixtureChildContracts(string profile) {
            string executable=Environment.ProcessPath,script=Path.GetFullPath("tests/helpers/LaunchBoundFixture.ps1");
            Require(Path.GetDirectoryName(FixtureDiagnosticPath(@"C:\fixture","launch-observation.json"))==@"C:\fixture\launch-diagnostics","Fixture diagnostics entered marker set.");
            var args=Arguments(script,"child",@"C:\space path\é😀",profile,new string('a',32)).Take(10).ToArray();
            string command=JobOwner.Quote(executable)+" "+String.Join(" ",args.Select(JobOwner.Quote));
            foreach(string failure in new[]{"none","parent-outside","invalid-pipe","minus-pipe","nonpipe","duplicate-alias","not-inheritable","duplicate-nonpipe","pipe-11","pipe-12","nul","nul-invalid","nul-not-inheritable","attribute-zero","attribute-capacity","initialize","update","create","partial-create","create-throw","process-only","thread-only","member-false","member-query","rollback","delete","close","process-close","observe"}) {
                var calls=new FixtureChildFault{Failure=failure,ExpectedCommand=command};bool threw=false;
                try{StartFixtureDescendant(executable,args,profile,calls);}catch(AggregateException){threw=true;}catch(InvalidOperationException){threw=true;}
                Require(threw==(failure!="none"),"Fixture launch failure hidden/invented.");
                Require(calls.Events.Contains("observe")==new[]{"none","delete","close","process-close","observe"}.Contains(failure),"Fixture original-handle observation coverage changed.");
                int expectedClosed=new[]{"parent-outside","invalid-pipe","minus-pipe","nonpipe","duplicate-alias","pipe-11"}.Contains(failure)?0:new[]{"not-inheritable","duplicate-nonpipe","pipe-12"}.Contains(failure)?1:new[]{"nul","nul-invalid"}.Contains(failure)?2:calls.Created?5:3;
                if(new[]{"process-close","process-only","thread-only"}.Contains(failure))expectedClosed=4;
                Require(calls.Closed.Count==expectedClosed && calls.Closed.Distinct().Count()==expectedClosed,"Fixture owned-handle cleanup incomplete.");
                Require(calls.RollbackAttempted==(calls.Created && failure!="none" && failure!="thread-only"),"Fixture original-process rollback coverage changed.");
                Require(calls.Deleted==!(new[]{"parent-outside","invalid-pipe","minus-pipe","nonpipe","duplicate-alias","not-inheritable","duplicate-nonpipe","pipe-11","pipe-12","nul","nul-invalid","nul-not-inheritable","attribute-zero","attribute-capacity","initialize"}.Contains(failure)),"Attribute initialization/deletion contract changed.");
            }
            foreach(string bad in new[]{"--parent-pid=0","--parent-pid="+(Environment.ProcessId+1)}) { var vector=(string[])args.Clone();vector[9]=bad;bool rejected=false;try{StartFixtureDescendant(executable,vector,profile,new FixtureChildFault());}catch(InvalidOperationException){rejected=true;}Require(rejected,"Fixture parent spoof accepted."); }
        }
        static readonly JsonSerializerOptions json=new JsonSerializerOptions{IncludeFields=true,WriteIndented=true};
        static void Write(string path,object data) { using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write)) JsonSerializer.Serialize(f,data,json); }
        static void Require(bool value,string label) { if(!value) throw new InvalidOperationException(label); }
        public static ulong AvailablePhysicalMemory() { var m=new Native.SystemMemory{length=(uint)Marshal.SizeOf<Native.SystemMemory>()};Native.Check(Native.GlobalMemoryStatusEx(ref m));return m.available; }
        static void WaitFile(string dir,string name) {
            var clock=Stopwatch.StartNew(); while(!File.Exists(Path.Combine(dir,name))) { if(clock.ElapsedMilliseconds>=5000) throw new TimeoutException("Fixture not ready."); Thread.Sleep(10); }
        }
        static string EncodeFixtureValue(string value) { return Convert.ToBase64String(new UTF8Encoding(false,true).GetBytes(value)); }
        static string[] Arguments(string script,string mode,string dir,string profile,string run,string echo="") { return new[]{"-NoLogo","-NoProfile","-NonInteractive","-File",script,"--mode="+mode,"--directory-b64="+EncodeFixtureValue(dir),"--user-data-dir="+profile,"--fixture-run="+run,"--parent-pid="+Environment.ProcessId,"--echo-b64="+EncodeFixtureValue(echo)}; }
        sealed class FixtureTarget {
            internal readonly string Executable,Script,Manifest,ProductHash;
            internal FixtureTarget(string executable,string script,string manifest=null,string hash=null) {Executable=executable;Script=script;Manifest=manifest;ProductHash=hash;}
            internal string[] Args(string mode,string dir,string profile,string run,string echo="") {
                if(Manifest==null)return Arguments(Script,mode,dir,profile,run,echo);
                Require(Path.IsPathFullyQualified(Executable) && Path.IsPathFullyQualified(Manifest) && Path.GetDirectoryName(Executable)==Path.GetDirectoryName(Manifest) && Path.GetFileName(Executable)=="LaunchBoundFixture.exe" && Path.GetFileName(Manifest)=="fixture.product.json" && ProductHash!=null && ProductHash.Length==64,"Controlled product paths invalid.");
                byte[] bytes=File.ReadAllBytes(Manifest);Require(bytes.Length<=65536 && Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant()==ProductHash,"Controlled product manifest changed.");
                return new[]{"--mode="+mode,"--directory-b64="+EncodeFixtureValue(dir),"--user-data-dir="+profile,"--fixture-run="+run,"--parent-pid="+Environment.ProcessId,"--product-b64="+EncodeFixtureValue(Manifest),"--product-sha256="+ProductHash,"--echo-b64="+EncodeFixtureValue(echo)};
            }
        }
        static Snapshot StartFixture(JobOwner owner,FixtureTarget target,string mode,string dir,string profile) {
            string control=Path.Combine(dir,"control");Directory.CreateDirectory(control);var arguments=target.Args(mode,dir,profile,owner.RunId);
            Write(Path.Combine(control,"launch.json"),new{Executable=target.Executable,Arguments=arguments,RunId=owner.RunId});
            try{return owner.Start(target.Executable,arguments,profile);}
            catch(Exception error){
                try{Write(Path.Combine(control,"launch-failure.json"),new{ExceptionType=error.GetType().Name,Diagnostic=owner.ReadFailureDiagnostic()});}
                catch(Exception captureError){Write(Path.Combine(control,"diagnostic-unavailable.json"),new{OriginalExceptionType=error.GetType().Name,CaptureExceptionType=captureError.GetType().Name});}
                throw;
            }
        }
        static Marker ReadMarker(string path) {using(var doc=JsonDocument.Parse(File.ReadAllText(path))) {var m=doc.RootElement;return new Marker{Pid=m.GetProperty("pid").GetInt32(),Parent=m.GetProperty("parent").GetInt32(),Creation=m.GetProperty("creationFileTime").GetString(),Image=m.GetProperty("image").GetString(),Run=m.GetProperty("runId").GetString(),Mode=m.GetProperty("mode").GetString(),Product=m.TryGetProperty("productSha256",out var product)?product.GetString():null};}}
        static void ValidateRoleGraph(Marker root,Marker[] members,int[] pids,string mode,string run,string image,string product,int parent) {
            Require(new[]{"root","late","fanout"}.Contains(mode) && root.Mode==mode && root.Parent==parent && root.Pid>0 && !pids.Contains(root.Pid),"Fixture root role/parent invalid.");
            int expected=mode=="fanout"?3:2;
            Require(members.Length==expected && pids.Length==expected && pids.Distinct().Count()==expected && members.Select(m=>m.Pid).Distinct().Count()==expected && members.Select(m=>m.Pid).OrderBy(pid=>pid).SequenceEqual(pids.OrderBy(pid=>pid)),"Fixture role membership incomplete.");
            foreach(var marker in members.Concat(new[]{root})){long created;Require(marker.Pid>0 && marker.Parent>0 && Int64.TryParse(marker.Creation,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out created) && created>0 && marker.Run==run && marker.Product==product && String.Equals(marker.Image,image,StringComparison.OrdinalIgnoreCase),"Fixture role identity invalid.");}
            if(mode=="fanout")Require(members.All(marker=>marker.Mode=="hold" && marker.Parent==root.Pid),"Fanout role graph invalid.");
            else {var child=members.Where(marker=>marker.Mode=="child").ToArray();var grandchild=members.Where(marker=>marker.Mode=="grandchild").ToArray();Require(child.Length==1 && grandchild.Length==1 && child[0].Parent==root.Pid && grandchild[0].Parent==child[0].Pid,"Descendant role graph invalid.");}
        }
        static void RoleGraphContracts() {
            foreach(string mode in new[]{"root","late","fanout"})foreach(string fault in new[]{"none","root-mode","root-parent","root-live","role","parent","duplicate","run","product","creation","image"}) {
                string image=@"C:\product\LaunchBoundFixture.exe",run=new string('a',32),product=new string('b',64);
                var root=new Marker{Pid=10,Parent=9,Mode=mode,Creation="1",Image=image,Run=run,Product=product};
                var members=Enumerable.Range(0,mode=="fanout"?3:2).Select(i=>new Marker{Pid=11+i,Parent=mode=="fanout"||i==0?10:11,Mode=mode=="fanout"?"hold":i==0?"child":"grandchild",Creation="2",Image=image,Run=run,Product=product}).ToArray();
                int[] pids=members.Select(m=>m.Pid).ToArray();
                switch(fault){case "root-mode":root.Mode="hold";break;case "root-parent":root.Parent=8;break;case "root-live":pids[0]=10;break;case "role":members[0].Mode="grandchild";break;case "parent":members[0].Parent=12;break;case "duplicate":members[1].Pid=11;break;case "run":members[0].Run=new string('c',32);break;case "product":root.Product=new string('c',64);break;case "creation":members[0].Creation="0";break;case "image":root.Image=@"C:\other.exe";break;}
                bool rejected=false;try{ValidateRoleGraph(root,members,pids,mode,run,image,product,9);}catch(InvalidOperationException){rejected=true;}Require(rejected==(fault!="none"),"Fixture role graph rejection coverage changed.");
            }
        }
        static ExitObserver Census(JobOwner owner,Snapshot proof,string dir,FixtureTarget target,string mode,string[] markerFiles=null) {
            markerFiles=markerFiles??Directory.GetFiles(dir,"*.json");
            Write(Path.Combine(dir,"proof.json"),proof);
            if(proof.Pids.Length==0 || proof.Pids.Length>128) {Write(Path.Combine(dir,"census.json"),new{Proof=proof,Members=proof.Pids.Length==0?new[]{new MemberIdentity{State="empty-membership-unknown"}}:proof.Pids.Select(pid=>new MemberIdentity{Pid=pid,State="inspection-capacity-unknown"}).ToArray()});throw new InvalidOperationException("Census inspection unavailable.");}
            var markers=new Dictionary<int,Marker>();var errors=new List<string>();
            foreach(var p in markerFiles) {
                try {var marker=ReadMarker(p);markers.Add(marker.Pid,marker);}
                catch { errors.Add(Path.GetFileName(p)); }
            }
            var ledger=new ExitObserver(proof.Pids,proof.Pids.Select(pid=>markers.ContainsKey(pid)?markers[pid].Creation:null).ToArray(),owner.DiagnosticMember);
            // Persist the complete returned census, including unclassified/unreadable identities, before assertions.
            Write(Path.Combine(dir,"census.json"),new{OwnerPid=Environment.ProcessId,Proof=proof,Members=ledger.Members,MarkerReadErrors=errors});
            try {
                Require(errors.Count==0 && ledger.Ready && ledger.AllLive(),"Census identity unknown.");
                Require(markers.Count==proof.Pids.Length+1,"Unexpected fixture marker inventory.");
                ValidateRoleGraph(ReadMarker(Path.Combine(dir,mode+".json")),proof.Pids.Select(pid=>markers[pid]).ToArray(),proof.Pids,mode,owner.RunId,target.Executable,target.ProductHash,Environment.ProcessId);
                foreach(var item in ledger.Members) {
                    var marker=markers[item.Pid];
                    Require(item.Membership=="member" && item.ParentPid==marker.Parent && marker.Run==owner.RunId && String.Equals(item.ImagePath,target.Executable,StringComparison.OrdinalIgnoreCase) && String.Equals(item.ImagePath,marker.Image,StringComparison.OrdinalIgnoreCase),"Unexplained fixture member.");
                    if(target.Manifest!=null){var birth=ReadMarker(Path.Combine(dir,"launch-diagnostics","birth-"+item.Pid+".json"));Require(marker.Product==target.ProductHash && birth.Product==target.ProductHash && birth.Pid==item.Pid && birth.Parent==item.ParentPid && birth.Creation==item.CreationFileTime && birth.Run==owner.RunId && birth.Mode==marker.Mode && String.Equals(birth.Image,item.ImagePath,StringComparison.OrdinalIgnoreCase),"Original child birth identity mismatch.");}
                }
                Require(proof.Pids.SequenceEqual(owner.Query(5000).Pids) && ledger.AllLive(),"Fixture changed during identity binding.");
                return ledger;
            } catch { ledger.Dispose(); throw; }
        }
        public static void AssertBreakawayDenied(string executable,string script,string dir,string profile,string run) {
            var si=new Native.SIX{startup=new Native.SI{cb=Marshal.SizeOf<Native.SI>()}};Native.PI pi;
            string command=JobOwner.Quote(executable)+" "+String.Join(" ",Arguments(script,"hold",dir,profile,run).Select(JobOwner.Quote));
            if(!Native.CreateProcessW(executable,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,0x09000000,IntPtr.Zero,Path.GetDirectoryName(executable),ref si,out pi)) {
                int error=Marshal.GetLastWin32Error();Require(error==5,"Unexpected breakaway error.");return;
            }
            using(var process=new KernelHandle(pi.process))using(var thread=new KernelHandle(pi.thread)) {
                Native.Check(Native.TerminateProcess(process,125));Require(Native.WaitForSingleObject(process,5000)==0,"Unexpected breakaway rollback unknown.");
            }
            throw new InvalidOperationException("Breakaway unexpectedly permitted.");
        }
        public static void OfflineContracts(string profile) {
            RoleGraphContracts();
            FixtureChildContracts(profile);
            var prefix=JobOwner.DiagnosticPrefix(new StreamData{Bytes=99999,Text=new string('é',20000),Eof=true});
            Require(prefix.Bytes==99999 && prefix.Eof && prefix.Truncated && !prefix.Failed && prefix.Text.Length==8192 && Encoding.UTF8.GetByteCount(prefix.Text)<=32768,"Diagnostic prefix bound changed.");
            Require(JobOwner.DiagnosticPrefix(null).Failed && !JobOwner.DiagnosticPrefix(null).Eof,"Missing drain became empty success.");
            JobOwner.ValidateProfileArguments(new[]{"--headless=new","--user-data-dir="+profile,"about:blank"},profile);
            foreach(string value in new[]{"",@"C:\space path\é",@"\\server\share\path", "colon:value quote\" whitespace\t unicode-é😀", "\uFEFFleading BOM"}) {
                var args=Arguments("fixture.ps1","exit",value,profile,new string('a',32),value);
                Require(args[6]=="--directory-b64="+EncodeFixtureValue(value) && args[7]=="--user-data-dir="+profile && args[10]=="--echo-b64="+EncodeFixtureValue(value),"Fixture constructor changed value/profile contract.");
                Require(new UTF8Encoding(false,true).GetString(Convert.FromBase64String(args[6].Substring("--directory-b64=".Length)))==value,"Fixture constructor UTF-8 value changed.");
                JobOwner.ValidateProfileArguments(args,profile);
            }
            // Chromium trims these 25 Unicode whitespace characters before recognizing a switch.
            foreach(char whitespace in new[]{'\u0009','\u000A','\u000B','\u000C','\u000D','\u0020','\u0085','\u00A0','\u1680','\u2000','\u2001','\u2002','\u2003','\u2004','\u2005','\u2006','\u2007','\u2008','\u2009','\u200A','\u2028','\u2029','\u202F','\u205F','\u3000'}) {
                foreach(string switchPrefix in new[]{"--","-","/"}) {
                    foreach(string candidate in new[]{whitespace+switchPrefix+"UsEr-DaTa-DiR="+profile,switchPrefix+"UsEr-DaTa-DiR="+profile+whitespace,whitespace+switchPrefix+"UsEr-DaTa-DiR="+profile+whitespace}) {
                        bool rejected=false;try{JobOwner.ValidateProfileArguments(new[]{"--user-data-dir="+profile,candidate},profile);}catch(ArgumentException){rejected=true;}Require(rejected,"Whitespace profile override accepted.");
                    }
                }
                bool trailingRejected=false;try{JobOwner.ValidateProfileArguments(new[]{"--user-data-dir="+profile+whitespace},profile);}catch(ArgumentException){trailingRejected=true;}Require(trailingRejected,"Trailing profile whitespace accepted.");
                foreach(string separator in new[]{whitespace+"--","--"+whitespace,whitespace+"--"+whitespace}) {
                    bool separatorRejected=false;try{JobOwner.ValidateProfileArguments(new[]{"--user-data-dir="+profile,separator},profile);}catch(ArgumentException){separatorRejected=true;}Require(separatorRejected,"Whitespace separator accepted.");
                }
                JobOwner.ValidateProfileArguments(new[]{"--user-data-dir="+profile,whitespace+"unrelated-value"},profile);
            }
            foreach(string malformed in new[]{"---user-data-dir=","//user-data-dir=","-/user-data-dir="}) {
                bool rejected=false;try{JobOwner.ValidateProfileArguments(new[]{"--user-data-dir="+profile,malformed+profile},profile);}catch(ArgumentException){rejected=true;}Require(rejected,"Malformed profile prefix accepted.");
            }
            foreach(var args in new[]{new[]{"--USER-DATA-DIR="+profile},new[]{"--user-data-dir="+profile,"--User-Data-Dir="+profile},new[]{"--user-data-dir="+profile,"--user-data-dir="+profile},new[]{"--user-data-dir",profile},new[]{"--user-data-dir="},new[]{"--user-data-dir=relative"},new[]{"--","--user-data-dir="+profile},new[]{"--user-data-dir="+profile,"--"},new[]{"/user-data-dir="+profile},new[]{"-user-data-dir="+profile}}) {
                bool rejected=false;try{JobOwner.ValidateProfileArguments(args,profile);}catch(ArgumentException){rejected=true;}Require(rejected,"Ambiguous profile accepted.");
            }
            Require(JobOwner.ValidateOuterPolicy(0x2200,2UL*1024*1024*1024,0)==2L*1024*1024*1024,"Correct policy rejected.");
            foreach(uint flags in new uint[]{0,0x2000,0x2200|0x800,0x2200|0x1000}) {bool rejected=false;try{JobOwner.ValidateOuterPolicy(flags,2UL*1024*1024*1024,0);}catch(InvalidOperationException){rejected=true;}Require(rejected,"Unsafe outer policy accepted.");}
            foreach(var pair in new[]{(1UL,0U),(2UL*1024*1024*1024,1U)}) {bool rejected=false;try{JobOwner.ValidateOuterPolicy(0x2200,pair.Item1,pair.Item2);}catch(InvalidOperationException){rejected=true;}Require(rejected,"Wrong cap/UI accepted.");}
        }
        public static string[] Run(string executable,string script,string directory,int neighborPid,bool diagnosticOnly) {
            return Run(new FixtureTarget(executable,script),directory,neighborPid,diagnosticOnly);
        }
        public static string[] RunControlled(string executable,string manifest,string manifestHash,string directory,int neighborPid,bool diagnosticOnly) {
            return Run(new FixtureTarget(executable,null,manifest,manifestHash),directory,neighborPid,diagnosticOnly);
        }
        // Mandatory real-PowerShell integration complements the controlled topology.
        // This proves captured execution/completion, not arbitrary PowerShell host provenance.
        public static string[] RunPowerShellIntegration(string executable,string script,string directory) {
            var results=new List<string>();var target=new FixtureTarget(executable,script);string current="setup";
            try {
                foreach(string mode in new[]{"exit","output","early-error","early-error-output"}) {
                    current=mode;string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);
                    using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,mode.StartsWith("early-error",StringComparison.Ordinal)?new FirstCensus(dir):new NativeCalls())) {
                        if(mode.StartsWith("early-error",StringComparison.Ordinal)) {
                            bool threw=false;try{StartFixture(owner,target,mode,dir,profile);}catch{threw=true;}
                            var diagnostic=owner.ReadFailureDiagnostic();Write(Path.Combine(dir,"powerShell-diagnostic.json"),diagnostic);
                            Require(threw && diagnostic.RollbackContained && diagnostic.RetainedRootWaitResult==0 && diagnostic.RetainedRootExitCode==1 && diagnostic.DrainJoinCompleted && diagnostic.StdoutCompleted && diagnostic.StderrCompleted && diagnostic.Stdout.Eof && diagnostic.Stderr.Eof && !diagnostic.Stdout.Failed && !diagnostic.Stderr.Failed && !diagnostic.Setup.Confirmed,"PowerShell failed-start completion unknown.");
                            Require(Encoding.UTF8.GetByteCount(diagnostic.Stderr.Text)<=32768,"PowerShell failure prefix unbounded.");
                            if(mode=="early-error-output")Require(diagnostic.Stderr.Bytes>131072 && diagnostic.Stderr.Truncated,"PowerShell oversized failure diagnostic lost.");
                            else Require(diagnostic.Stderr.Text.Contains("fixture-failure phase=children"),"PowerShell diagnostic phase lost.");
                        } else {
                            string echo="spaces quote\" trailing\\ unicode-é😀";var captured=owner.RunCaptured(executable,target.Args(mode,dir,profile,owner.RunId,echo),profile,15000);
                            Write(Path.Combine(dir,"powerShell-capture.json"),captured);
                            Require(captured.Started && !captured.TimedOut && captured.ExitCode==0 && captured.Completion.Confirmed && captured.Completion.Pids.Length==0 && captured.Completion.StreamsComplete && captured.Stdout.Eof && captured.Stderr.Eof && !captured.Stdout.Failed && !captured.Stderr.Failed,"PowerShell capture completion unknown.");
                            if(mode=="exit")Require(captured.Stdout.Text==echo+Environment.NewLine,"PowerShell Unicode/argv contents changed.");
                            else Require(captured.Stdout.Bytes==64*1024*1024+1 && captured.Stderr.Bytes==64*1024+1 && captured.Stdout.Truncated && captured.Stderr.Truncated && captured.Stdout.Text.Length==64*1024*1024 && captured.Stderr.Text.Length==64*1024 && captured.Stdout.Text.All(ch=>ch=='x') && captured.Stderr.Text.All(ch=>ch=='e'),"PowerShell output bytes/contents incorrect.");
                        }
                        results.Add("powershell-"+mode+":capture-and-completion");
                    }
                }
                return results.ToArray();
            } catch(Exception error){Write(Path.Combine(directory,"failure.json"),new{Case=current,ExceptionType=error.GetType().Name,CompletedCases=results});throw;}
            finally{Write(Path.Combine(directory,"partial-cases.json"),new{CurrentCase=current,CompletedCases=results});}
        }
        static string[] Run(FixtureTarget target,string directory,int neighborPid,bool diagnosticOnly) {
            var results=new List<string>();string current="setup";Directory.CreateDirectory(directory);
            try {
                foreach(string mode in diagnosticOnly?new[]{"root"}:new[]{"root","late"}) {
                    current=mode;string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);
                    using(var owner=mode=="root"?new JobOwner(Guid.NewGuid().ToString("N"),profile,new FirstCensus(dir)):new JobOwner(Guid.NewGuid().ToString("N"),profile)) {
                        var proof=StartFixture(owner,target,mode,dir,profile);
                        Require(!owner.Contains(neighborPid),"Neighbor was assigned.");
                        if(mode=="late") {File.WriteAllText(Path.Combine(dir,"go"),"go");WaitFile(dir,"grandchild.json");WaitFile(dir,"root-done");Thread.Sleep(100);proof=owner.Query(5000);}
                        using(var ledger=Census(owner,proof,dir,target,mode)) {
                            Require(proof.ExitCode==0 && proof.ActiveProcesses==2 && !proof.Terminal && proof.WorkingSetBytes>0 && proof.PrivateBytes>0,"Root-exit descendants lost.");
                            Require(!proof.Pids.Contains(Environment.ProcessId),"Owner counted as fixture.");
                            var stopped=owner.Stop(5000);bool exited=ledger.Wait(5000);Write(Path.Combine(dir,"completion.json"),new{Stopped=stopped,OriginalHandlesExited=exited});
                            Require(stopped.Confirmed && stopped.Forced && stopped.Pids.Length==0 && stopped.StreamsComplete && exited,"Job did not complete.");
                            var repeated=owner.Stop(5000);Write(Path.Combine(dir,"repeated-completion.json"),repeated);Require(repeated.Confirmed,"Repeated completion failed.");results.Add(mode+":fully-identified-descendants-and-zero");
                        }
                    }
                }
                if(diagnosticOnly)return results.ToArray();
                foreach(string mode in new[]{"early-error","early-error-output"}) {
                    current=mode;string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);
                    using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,new FirstCensus(dir))) {
                        bool threw=false;try{StartFixture(owner,target,mode,dir,profile);}catch{threw=true;}
                        using(var doc=JsonDocument.Parse(File.ReadAllText(Path.Combine(dir,"control/launch-failure.json")))) {
                            var capture=doc.RootElement.GetProperty("Diagnostic");var stderr=capture.GetProperty("Stderr");
                            var stdout=capture.GetProperty("Stdout");
                            Require(threw && capture.GetProperty("RollbackContained").GetBoolean() && capture.GetProperty("RetainedRootWaitResult").GetUInt32()==0 && capture.GetProperty("RetainedRootExitCode").GetInt32()==1 && capture.GetProperty("DrainJoinCompleted").GetBoolean() && capture.GetProperty("StdoutCompleted").GetBoolean() && capture.GetProperty("StderrCompleted").GetBoolean() && stdout.GetProperty("Eof").GetBoolean() && !stdout.GetProperty("Failed").GetBoolean() && stderr.GetProperty("Eof").GetBoolean() && !stderr.GetProperty("Failed").GetBoolean() && !capture.GetProperty("Setup").GetProperty("Confirmed").GetBoolean(),"Failed-launch diagnostic/containment unknown.");
                            Require(Encoding.UTF8.GetByteCount(stderr.GetProperty("Text").GetString())<=32768,"Failure prefix unbounded.");
                            if(mode=="early-error-output")Require(stderr.GetProperty("Bytes").GetInt64()>131072 && stderr.GetProperty("Truncated").GetBoolean(),"Oversized failure stream not bounded.");
                            else Require(stderr.GetProperty("Text").GetString().Contains("fixture-failure phase=children"),"Fixture phase prefix missing.");
                        }
                        results.Add(mode+":contained-failure-diagnostic-preserved");
                    }
                }
                foreach(string mode in new[]{"assignment","missing-outer"}) {
                    current=mode;string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);var faults=new AssignmentFailure();
                    var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,mode=="assignment"?(NativeCalls)faults:new MissingOuter());bool threw=false;
                    try {StartFixture(owner,target,"exit",dir,profile);}catch{threw=true;}
                    try {Require(threw && owner.Setup.Created && !owner.Setup.Assigned && !owner.Setup.Resumed && !File.Exists(Path.Combine(dir,"exit.json")),"Preassign failure resumed.");if(mode=="assignment")Require(!owner.RollbackContained,"Initial rollback failure hidden.");}
                    finally{owner.Dispose();}
                    Require(owner.RollbackContained && (mode!="assignment" || faults.Terminations==2 && faults.Waits==2),"Retained root rollback failed.");owner.Dispose();results.Add(mode+":no-resume-original-handle-rollback");
                }
                {
                    current="fanout";string dir=Path.Combine(directory,current),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);var faults=new SmallCapacity();
                    using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,faults)) {
                        StartFixture(owner,target,"fanout",dir,profile);WaitFile(dir,"fanout-done");
                        var clock=Stopwatch.StartNew();while(Directory.GetFiles(dir,"hold-*.json").Length<3){if(clock.ElapsedMilliseconds>=5000)throw new TimeoutException("Fanout not ready.");Thread.Sleep(10);}
                        int rootPid;using(var marker=JsonDocument.Parse(File.ReadAllText(Path.Combine(dir,"fanout.json"))))rootPid=marker.RootElement.GetProperty("pid").GetInt32();
                        var proof=owner.Query(5000);while((proof.ExitCode==null||proof.ActiveProcesses!=3||proof.Pids.Contains(rootPid))&&clock.ElapsedMilliseconds<5000){Thread.Sleep(10);proof=owner.Query(5000);}
                        var markerFiles=Directory.GetFiles(dir,"*.json");
                        Write(Path.Combine(dir,"pid-capacities.json"),new{Attempts=faults.Attempts,TestInitialCapacity=2,ProductionInitialCapacity=32,ElapsedMilliseconds=clock.ElapsedMilliseconds,RootPid=rootPid,Proof=proof,Converged=proof.ExitCode!=null&&proof.ActiveProcesses==3&&!proof.Pids.Contains(rootPid)&&clock.ElapsedMilliseconds<5000});
                        using(var ledger=Census(owner,proof,dir,target,"fanout",markerFiles)) {
                            Require(clock.ElapsedMilliseconds<5000 && proof.ExitCode!=null && proof.ActiveProcesses==3 && !proof.Pids.Contains(rootPid),"Fanout root exit/membership unknown.");
                            Require(faults.Attempts.Contains(2) && faults.Attempts.Contains(4),"Real PID buffer growth not exercised.");var stopped=owner.Stop(5000);bool exited=ledger.Wait(5000);Write(Path.Combine(dir,"completion.json"),new{Stopped=stopped,OriginalHandlesExited=exited});Require(stopped.Confirmed && stopped.Pids.Length==0 && stopped.StreamsComplete && exited,"Fanout completion unknown.");
                        }
                        results.Add("fanout:three-"+(target.Manifest==null?"pwsh":"controlled")+"-members-real-growth-seed2-production-default32-unchanged");
                    }
                }
                foreach(string fault in new[]{"late-query","query-error","negative-memory","open-error","memory-error"}) {
                    current=fault;string dir=Path.Combine(directory,fault),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);var faults=new QueryFault();
                    using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,faults)) {
                        StartFixture(owner,target,fault=="late-query"?"exit":"hold",dir,profile);
                        if(fault=="late-query"){owner.Stop(5000);faults.Delay=true;}else if(fault=="query-error")faults.Bad=true;else if(fault=="negative-memory")faults.Negative=true;else if(fault=="open-error")faults.OpenError=true;else faults.MemoryError=true;
                        bool threw=false;int? code=null;try{owner.Query(fault=="late-query"?5:5000);}catch(Win32Exception error){threw=true;code=error.NativeErrorCode;}catch{threw=true;}
                        Require(threw && (!(fault=="open-error"||fault=="memory-error")||code==5),"Failure or original native error lost.");
                        bool confirmed=false;try{confirmed=owner.Stop(5000).Confirmed;}catch{}Require(!confirmed,"Failed query state reset.");results.Add(fault+":sticky-unknown-original-error-preserved");
                    }
                }
                foreach(string mode in new[]{"exit","output","breakaway"}) {
                    current=mode;string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile");Directory.CreateDirectory(profile);
                    using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile)) {
                        string echo="spaces quote\" trailing\\ unicode-é😀";var captured=owner.RunCaptured(target.Executable,target.Args(mode,dir,profile,owner.RunId,echo),profile,15000);
                        Write(Path.Combine(dir,"capture.json"),captured);
                        Require(captured.Started && !captured.TimedOut && captured.Completion.Confirmed && captured.Completion.StreamsComplete && captured.ExitCode==0,"Capture incomplete.");
                        if(mode=="exit")Require(captured.Stdout.Text==echo+(target.Manifest==null?Environment.NewLine:"\n"),"Native argv/Unicode quoting failed.");
                        if(mode=="output")Require(captured.Stdout.Bytes==64*1024*1024+1 && captured.Stderr.Bytes==64*1024+1 && captured.Stdout.Truncated && captured.Stderr.Truncated && Encoding.UTF8.GetByteCount(captured.Stdout.Text)==64*1024*1024 && Encoding.UTF8.GetByteCount(captured.Stderr.Text)==64*1024 && captured.Stdout.Text.All(ch=>ch=='x') && captured.Stderr.Text.All(ch=>ch=='e'),"Bounded drains incorrect.");
                        if(mode=="breakaway")Require(File.Exists(Path.Combine(dir,"breakaway-denied")),"Breakaway not rejected.");results.Add(mode+":capture-zero");
                    }
                }
                return results.ToArray();
            } catch(Exception error) {Write(Path.Combine(directory,"failure.json"),new{Case=current,ExceptionType=error.GetType().Name,CompletedCases=results});throw;}
            finally{Write(Path.Combine(directory,"partial-cases.json"),new{CurrentCase=current,CompletedCases=results});}
        }
    }
}
