// Synthetic Windows GUI-subsystem fixture. No UI, console allocation, job assignment or general launcher.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using LaunchBound;

namespace LaunchBoundTests {
    public static class ControlledFixture {
        static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
        static readonly JsonSerializerOptions Json=new JsonSerializerOptions{IncludeFields=true};
        static readonly string[] Modes={"root","late","child","grandchild","hold","fanout","exit","output","breakaway","early-error","early-error-output"};
        static readonly string[] ProductFiles={"LaunchBoundFixture.exe","LaunchBoundFixture.dll","LaunchBoundFixture.deps.json","LaunchBoundFixture.runtimeconfig.json"};
        [StructLayout(LayoutKind.Sequential)] struct Basic { public IntPtr exit,peb,affinity,priority,pid,parent; }
        [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr process,int kind,out Basic value,int size,out int returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder value,ref uint size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetStdHandle(int slot);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr duplicate,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll",EntryPoint="WaitForSingleObject",SetLastError=true)] static extern uint Wait(IntPtr process,uint milliseconds);
        [DllImport("kernel32.dll",EntryPoint="TerminateProcess",SetLastError=true)] static extern bool Terminate(IntPtr process,uint code);
        [DllImport("kernel32.dll",EntryPoint="ResumeThread",SetLastError=true)] static extern uint Resume(IntPtr thread);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(IntPtr handle,IntPtr bytes,uint count,out uint written,IntPtr overlapped);
        sealed class Options {
            internal string Mode,Directory,Profile,Run,Manifest,ManifestHash,Echo;
            internal int Parent;
        }
        static void Require(bool value,string message) { if(!value)throw new InvalidOperationException(message); }
        static bool Handle(IntPtr value) { return value!=IntPtr.Zero && value!=new IntPtr(-1); }
        static string Hash(byte[] value) { return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant(); }
        static bool Hex(string value,int count) { return value!=null && value.Length==count && value.All(ch=>ch>='0'&&ch<='9'||ch>='a'&&ch<='f'); }
        static string Decode(string value) {
            byte[] bytes=Convert.FromBase64String(value);Require(Convert.ToBase64String(bytes)==value,"Noncanonical fixture encoding.");
            string decoded=Utf8.GetString(bytes);Require(decoded.IndexOf('\0')<0,"NUL fixture value.");return decoded;
        }
        static string Encode(string value) { return Convert.ToBase64String(Utf8.GetBytes(value)); }
        static Options Parse(string[] args) {
            var values=new Dictionary<string,string>(StringComparer.Ordinal);
            foreach(string value in args) {
                Require(value!=null && value.StartsWith("--",StringComparison.Ordinal) && value.IndexOf('\0')<0,"Invalid fixture argument.");
                int equal=value.IndexOf('=');Require(equal>2,"Missing fixture value.");
                string name=value.Substring(2,equal-2);Require(new[]{"mode","directory-b64","user-data-dir","fixture-run","parent-pid","product-b64","product-sha256","echo-b64"}.Contains(name) && !values.ContainsKey(name),"Unknown or duplicate fixture argument.");values.Add(name,value.Substring(equal+1));
            }
            Require(values.Count==8,"Incomplete fixture argument set.");
            var o=new Options{Mode=values["mode"],Directory=Decode(values["directory-b64"]),Profile=values["user-data-dir"],Run=values["fixture-run"],Manifest=Decode(values["product-b64"]),ManifestHash=values["product-sha256"],Echo=Decode(values["echo-b64"])};
            Require(Modes.Contains(o.Mode) && Hex(o.Run,32) && Hex(o.ManifestHash,64) && Int32.TryParse(values["parent-pid"],NumberStyles.None,CultureInfo.InvariantCulture,out o.Parent) && o.Parent>0,"Invalid fixture identity.");
            Require(Path.IsPathFullyQualified(o.Directory) && Path.IsPathFullyQualified(o.Profile) && Path.IsPathFullyQualified(o.Manifest),"Absolute fixture paths required.");
            Require(String.Equals(Path.GetFullPath(o.Profile),Path.Combine(Path.GetFullPath(o.Directory),"profile"),StringComparison.OrdinalIgnoreCase),"Fixture profile is not in its family directory.");
            JobOwner.ValidateProfileArguments(args,o.Profile);return o;
        }
        public static string[] Arguments(string mode,string directory,string profile,string run,int parent,string manifest,string manifestHash,string echo="") {
            return new[]{"--mode="+mode,"--directory-b64="+Encode(directory),"--user-data-dir="+profile,"--fixture-run="+run,"--parent-pid="+parent.ToString(CultureInfo.InvariantCulture),"--product-b64="+Encode(manifest),"--product-sha256="+manifestHash,"--echo-b64="+Encode(echo)};
        }
        static byte[] ReadBounded(string path,int maximum) {
            using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                Require(file.Length>0 && file.Length<=maximum,"Fixture product size invalid.");var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);return bytes;
            }
        }
        public static string VerifyProduct(string executable,string manifest,string manifestHash) {
            Require(OperatingSystem.IsWindows() && Path.IsPathFullyQualified(executable) && Path.IsPathFullyQualified(manifest) && Hex(manifestHash,64),"Invalid fixture product binding.");
            string root=Path.GetDirectoryName(Path.GetFullPath(executable));
            Require(Path.GetFileName(executable)==ProductFiles[0] && String.Equals(Path.GetDirectoryName(Path.GetFullPath(manifest)),root,StringComparison.OrdinalIgnoreCase) && Path.GetFileName(manifest)=="fixture.product.json","Fixture product path mismatch.");
            byte[] manifestBytes=ReadBounded(manifest,65536);Require(Hash(manifestBytes)==manifestHash,"Fixture product manifest changed.");
            using(var doc=JsonDocument.Parse(manifestBytes)) {
                var value=doc.RootElement;Require(value.GetProperty("schema").GetInt32()==1 && value.GetProperty("runtimeVersion").GetString()=="10.0.12" && Hex(value.GetProperty("sourceSha256").GetString(),64),"Fixture product schema/runtime mismatch.");
                string runtimeDirectory=value.GetProperty("runtimeDirectory").GetString();Require(Path.IsPathFullyQualified(runtimeDirectory),"Fixture runtime directory is not absolute.");
                var files=value.GetProperty("files").EnumerateArray().ToArray();Require(files.Length==4,"Fixture product closure incomplete.");
                for(int i=0;i<files.Length;i++) {
                    Require(files[i].GetProperty("path").GetString()==ProductFiles[i],"Fixture product inventory changed.");
                    var bytes=ReadBounded(Path.Combine(root,ProductFiles[i]),1024*1024);
                    Require(files[i].GetProperty("bytes").GetInt64()==bytes.Length && files[i].GetProperty("sha256").GetString()==Hash(bytes),"Fixture product bytes changed.");
                    if(i==0) {
                        Require(bytes.Length>=256 && bytes[0]==0x4d && bytes[1]==0x5a,"Fixture apphost is not PE.");int pe=BitConverter.ToInt32(bytes,0x3c);
                        Require(pe>=64 && pe<=bytes.Length-94 && BitConverter.ToUInt32(bytes,pe)==0x00004550 && BitConverter.ToUInt16(bytes,pe+4)==0x8664 && BitConverter.ToUInt16(bytes,pe+24)==0x20b && BitConverter.ToUInt16(bytes,pe+24+68)==2,"Fixture apphost is not x64 GUI subsystem.");
                    }
                }
                return runtimeDirectory;
            }
        }
        static void WriteNew(string path,object value) {
            using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {JsonSerializer.Serialize(file,value,Json);file.Flush(true);}
        }
        static object Identity(IntPtr process,int pid,int parent,string run,string mode,string productHash) {
            long created,exited,kernel,user;Native.Check(GetProcessTimes(process,out created,out exited,out kernel,out user));
            var image=new StringBuilder(32768);uint size=(uint)image.Capacity;Native.Check(QueryFullProcessImageNameW(process,0,image,ref size));
            return new{pid,parent,creationFileTime=created.ToString(CultureInfo.InvariantCulture),image=image.ToString(),runId=run,mode,productSha256=productHash};
        }
        static int ParentPid() {
            Basic value;int returned;int status=NtQueryInformationProcess(Native.GetCurrentProcess(),0,out value,Marshal.SizeOf<Basic>(),out returned);
            Require(status==0 && returned==Marshal.SizeOf<Basic>(),"Fixture parent identity unavailable.");return checked((int)value.parent.ToInt64());
        }
        static void Marker(Options o) {
            string name=o.Mode=="hold"?"hold-"+Environment.ProcessId:o.Mode;
            string destination=Path.Combine(o.Directory,name+".json"),temporary=destination+".tmp";
            WriteNew(temporary,Identity(Native.GetCurrentProcess(),Environment.ProcessId,o.Parent,o.Run,o.Mode,o.ManifestHash));File.Move(temporary,destination);
        }
        static IntPtr DuplicatePipe(int slot) {
            IntPtr original=GetStdHandle(slot);Require(Handle(original) && GetFileType(original)==3,"Fixture captured pipe unavailable.");
            IntPtr duplicate=IntPtr.Zero;
            try { Native.Check(DuplicateHandle(Native.GetCurrentProcess(),original,Native.GetCurrentProcess(),out duplicate,0,true,2));uint flags;Native.Check(Native.GetHandleInformation(duplicate,out flags));Require(Handle(duplicate) && duplicate!=original && GetFileType(duplicate)==3 && (flags&1)!=0,"Fixture inherited pipe invalid.");return duplicate; }
            catch(Exception failure) { var errors=new List<Exception>{failure};if(Handle(duplicate) && duplicate!=original)Attempt(errors,()=>Native.Check(Native.CloseHandle(duplicate)));if(errors.Count>1)throw new AggregateException("Fixture duplicate validation/cleanup failed.",errors);throw; }
        }
        static void Rollback(IntPtr process) {
            uint wait=Wait(process,0);if(wait==0)return;Require(wait==258,"Fixture child wait unknown.");Native.Check(Terminate(process,125));Require(Wait(process,5000)==0,"Fixture child rollback unknown.");
        }
        static void Attempt(List<Exception> errors,Action work) { try{work();}catch(Exception error){errors.Add(error);} }
        // Narrow test seam around this fixture's actual suspended-child workflow.
        // It cannot be selected through arguments or production owner IPC.
        class ChildCalls {
            internal virtual bool InJob(IntPtr process) {bool member;Native.Check(Native.IsProcessInJob(process,IntPtr.Zero,out member));return member;}
            internal virtual IntPtr Duplicate(int slot) {return DuplicatePipe(slot);}
            internal virtual IntPtr NullInput() {var sa=new Native.SA{size=Marshal.SizeOf<Native.SA>(),inherit=true};var handle=Native.CreateFileW("NUL",0x80000000,3,ref sa,3,0,IntPtr.Zero);int error=Marshal.GetLastWin32Error();if(!Handle(handle))throw new Win32Exception(error);return handle;}
            internal virtual UIntPtr AttributeSize() {UIntPtr bytes=UIntPtr.Zero;Native.InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);return bytes;}
            internal virtual void Initialize(IntPtr list,ref UIntPtr bytes) {Native.Check(Native.InitializeProcThreadAttributeList(list,1,0,ref bytes));}
            internal virtual void SetHandles(IntPtr list,IntPtr handles) {Native.Check(Native.UpdateProcThreadAttribute(list,0,new UIntPtr(0x20002),handles,new UIntPtr((uint)(3*IntPtr.Size)),IntPtr.Zero,IntPtr.Zero));}
            internal virtual bool Create(string executable,StringBuilder command,uint flags,ref Native.SIX startup,out Native.PI pi) {return Native.CreateProcessW(executable,command,IntPtr.Zero,IntPtr.Zero,true,flags,IntPtr.Zero,Path.GetDirectoryName(executable),ref startup,out pi);}
            internal virtual void Birth(IntPtr process,uint pid,Options o,string mode) {string diagnostics=Path.Combine(o.Directory,"launch-diagnostics");Directory.CreateDirectory(diagnostics);WriteNew(Path.Combine(diagnostics,"birth-"+pid+".json"),Identity(process,checked((int)pid),Environment.ProcessId,o.Run,mode,o.ManifestHash));}
            internal virtual uint ResumeChild(IntPtr thread) {uint result=Resume(thread);int error=Marshal.GetLastWin32Error();if(result==UInt32.MaxValue)throw new Win32Exception(error);return result;}
            internal virtual void Delete(IntPtr list) {Native.DeleteProcThreadAttributeList(list);}
            internal virtual void Close(IntPtr handle) {Native.Check(Native.CloseHandle(handle));}
            internal virtual void RollbackChild(IntPtr process) {Rollback(process);}
        }
        static void Spawn(Options o,string mode,bool deniedBreakaway=false) {
            string executable=Environment.ProcessPath;VerifyProduct(executable,o.Manifest,o.ManifestHash);
            var calls=new ChildCalls();Require(calls.InJob(Native.GetCurrentProcess()),"Fixture parent outside containment.");Spawn(o,executable,mode,deniedBreakaway,calls);
        }
        static void Spawn(Options o,string executable,string mode,bool deniedBreakaway,ChildCalls calls) {
            Require(new[]{"child","grandchild","hold"}.Contains(mode),"Unsupported fixture child role.");
            string command=JobOwner.Quote(executable)+" "+String.Join(" ",Arguments(mode,o.Directory,o.Profile,o.Run,Environment.ProcessId,o.Manifest,o.ManifestHash).Select(JobOwner.Quote));Require(command.Length<32767,"Fixture child command too long.");
            IntPtr output=IntPtr.Zero,error=IntPtr.Zero,input=IntPtr.Zero,list=IntPtr.Zero,handles=IntPtr.Zero;Native.PI pi=default;bool initialized=false;var errors=new List<Exception>();
            try {
                output=calls.Duplicate(-11);error=calls.Duplicate(-12);input=calls.NullInput();Require(Handle(input),"Fixture NUL input unavailable.");
                UIntPtr bytes=calls.AttributeSize();Require(bytes.ToUInt64()>0 && bytes.ToUInt64()<=65536,"Fixture attribute capacity invalid.");
                list=Marshal.AllocHGlobal((int)bytes.ToUInt64());handles=Marshal.AllocHGlobal(3*IntPtr.Size);calls.Initialize(list,ref bytes);initialized=true;
                Marshal.WriteIntPtr(handles,input);Marshal.WriteIntPtr(handles,IntPtr.Size,output);Marshal.WriteIntPtr(handles,2*IntPtr.Size,error);calls.SetHandles(list,handles);
                var startup=new Native.SIX{startup=new Native.SI{cb=Marshal.SizeOf<Native.SIX>(),flags=0x100,input=input,output=output,error=error},attributes=list};
                bool created=calls.Create(executable,new StringBuilder(command),0x08080004U|(deniedBreakaway?0x01000000U:0U),ref startup,out pi);int nativeError=Marshal.GetLastWin32Error();
                if(deniedBreakaway) {Require(!created && nativeError==5,"Breakaway was not denied with access error.");}
                else {
                    if(!created)throw new Win32Exception(nativeError);
                    Require(Handle(pi.process) && Handle(pi.thread),"Fixture original handles missing.");Require(calls.InJob(pi.process),"Fixture child outside containment.");
                    calls.Birth(pi.process,pi.pid,o,mode);Require(calls.ResumeChild(pi.thread)==1,"Fixture unexpected child resume state.");
                }
            } catch(Exception failure){errors.Add(failure);}
            finally {
                if(initialized)Attempt(errors,()=>calls.Delete(list));
                if(list!=IntPtr.Zero)Attempt(errors,()=>Marshal.FreeHGlobal(list));if(handles!=IntPtr.Zero)Attempt(errors,()=>Marshal.FreeHGlobal(handles));
                foreach(IntPtr handle in new[]{input,error,output,pi.thread})if(Handle(handle))Attempt(errors,()=>calls.Close(handle));
                if((errors.Count>0 || deniedBreakaway) && Handle(pi.process))Attempt(errors,()=>calls.RollbackChild(pi.process));
                if(Handle(pi.process)){try{calls.Close(pi.process);}catch(Exception failure){errors.Add(failure);Attempt(errors,()=>calls.RollbackChild(pi.process));}}
            }
            if(errors.Count>0)throw new AggregateException("Fixture child launch/cleanup failed; job cleanup required.",errors);
        }
        delegate bool WriteOperation(IntPtr handle,IntPtr buffer,uint count,out uint written);
        static void WriteBuffer(IntPtr handle,byte[] bytes,WriteOperation write) {
            var pin=GCHandle.Alloc(bytes,GCHandleType.Pinned);
            try {int offset=0;while(offset<bytes.Length){uint written;Native.Check(write(handle,IntPtr.Add(pin.AddrOfPinnedObject(),offset),(uint)(bytes.Length-offset),out written));Require(written>0 && written<=bytes.Length-offset,"Fixture write made no progress.");offset+=checked((int)written);}}finally{pin.Free();}
        }
        static bool NativeWrite(IntPtr handle,IntPtr buffer,uint count,out uint written) { return WriteFile(handle,buffer,count,out written,IntPtr.Zero); }
        static void WriteBytes(int slot,byte[] bytes) {
            IntPtr handle=GetStdHandle(slot);Require(Handle(handle) && GetFileType(handle)==3,"Fixture output pipe unavailable.");WriteBuffer(handle,bytes,NativeWrite);
        }
        sealed class ChildFault : ChildCalls {
            internal string Failure;internal bool Breakaway,Created,Born,Resumed,RolledBack,Deleted;internal readonly List<IntPtr> Closed=new List<IntPtr>();
            internal override IntPtr Duplicate(int slot) {if(Failure=="duplicate" && slot==-12)throw new Win32Exception(5);return new IntPtr(slot==-11?101:102);}
            internal override IntPtr NullInput() {if(Failure=="nul")throw new Win32Exception(5);return new IntPtr(103);}
            internal override UIntPtr AttributeSize() {return new UIntPtr(Failure=="attribute-size"?0U:256U);}
            internal override void Initialize(IntPtr list,ref UIntPtr bytes) {if(Failure=="initialize")throw new InvalidOperationException("initialize");}
            internal override void SetHandles(IntPtr list,IntPtr handles) {Require(Marshal.ReadIntPtr(handles)==new IntPtr(103) && Marshal.ReadIntPtr(handles,IntPtr.Size)==new IntPtr(101) && Marshal.ReadIntPtr(handles,2*IntPtr.Size)==new IntPtr(102),"Fixture inherited handles changed.");if(Failure=="attributes")throw new InvalidOperationException("attributes");}
            internal override bool Create(string executable,StringBuilder command,uint flags,ref Native.SIX startup,out Native.PI pi) {
                Require(executable==@"C:\product\LaunchBoundFixture.exe" && flags==(Breakaway?0x09080004U:0x08080004U) && startup.startup.flags==0x100 && startup.startup.cb==Marshal.SizeOf<Native.SIX>() && startup.startup.input==new IntPtr(103) && startup.startup.output==new IntPtr(101) && startup.startup.error==new IntPtr(102) && startup.attributes!=IntPtr.Zero,"Controlled fixture startup changed.");
                Require(command.ToString()==JobOwner.Quote(executable)+" "+String.Join(" ",Arguments("child",@"C:\fixture",@"C:\fixture\profile",new string('a',32),Environment.ProcessId,@"C:\product\fixture.product.json",new string('b',64)).Select(JobOwner.Quote)),"Controlled fixture argv changed.");
                pi=default;if(Failure=="create" || Failure=="denied"){Marshal.SetLastPInvokeError(5);return false;}
                pi=new Native.PI{process=Failure=="thread-only"?IntPtr.Zero:new IntPtr(104),thread=Failure=="process-only"?IntPtr.Zero:new IntPtr(105),pid=123};Created=true;
                Marshal.SetLastPInvokeError(5);if(Failure=="create-throw")throw new Win32Exception(5);return Failure!="partial-create";
            }
            internal override bool InJob(IntPtr process) {Require(process==new IntPtr(104) && !Closed.Contains(process),"Fixture lost original membership handle.");if(Failure=="membership-error")throw new Win32Exception(5);return Failure!="membership-false";}
            internal override void Birth(IntPtr process,uint pid,Options o,string mode) {Require(process==new IntPtr(104) && pid==123 && !Closed.Contains(process) && !Resumed && o.Run==new string('a',32) && mode=="child","Birth identity/order changed.");if(Failure=="birth" || Failure=="rollback")throw new InvalidOperationException("birth");Born=true;}
            internal override uint ResumeChild(IntPtr thread) {Require(Born && thread==new IntPtr(105) && !Closed.Contains(thread),"Resume preceded birth identity.");if(Failure=="resume-error")throw new Win32Exception(5);Resumed=true;return Failure=="resume-state"?0U:1U;}
            internal override void Delete(IntPtr list) {Deleted=true;if(Failure=="delete")throw new InvalidOperationException("delete");}
            internal override void Close(IntPtr handle) {Require(handle.ToInt64()>=101 && handle.ToInt64()<=105 && !Closed.Contains(handle),"Fixture closed an unowned/repeated handle.");if(Failure=="process-close" && handle==new IntPtr(104))throw new InvalidOperationException("process-close");Closed.Add(handle);if(Failure=="close" && handle==new IntPtr(103))throw new InvalidOperationException("close");}
            internal override void RollbackChild(IntPtr process) {Require(process==new IntPtr(104) && !Closed.Contains(process),"Rollback lost original child handle.");RolledBack=true;if(Failure=="rollback")throw new InvalidOperationException("rollback");}
        }
        static void ChildContracts() {
            var options=new Options{Directory=@"C:\fixture",Profile=@"C:\fixture\profile",Run=new string('a',32),Manifest=@"C:\product\fixture.product.json",ManifestHash=new string('b',64)};
            foreach(string failure in new[]{"none","duplicate","nul","attribute-size","initialize","attributes","create","partial-create","create-throw","thread-only","process-only","membership-error","membership-false","birth","resume-error","resume-state","delete","close","process-close","rollback","denied","unexpected-breakaway"}) {
                var calls=new ChildFault{Failure=failure,Breakaway=failure=="denied"||failure=="unexpected-breakaway"};AggregateException caught=null;
                try{Spawn(options,@"C:\product\LaunchBoundFixture.exe","child",calls.Breakaway,calls);}catch(AggregateException error){caught=error;}
                Require((caught==null)==(failure=="none"||failure=="denied"),"Child failure hidden/invented.");
                int expectedClosed=failure=="duplicate"?1:failure=="nul"?2:!calls.Created?3:failure=="thread-only"||failure=="process-only"||failure=="process-close"?4:5;
                Require(calls.Closed.Count==expectedClosed,"Fixture child cleanup lost handles.");
                Require(calls.RolledBack==(calls.Created && failure!="none" && failure!="thread-only"),"Child rollback coverage changed.");
                Require(calls.Resumed==new[]{"none","resume-state","delete","close","process-close"}.Contains(failure),"Failed child resumed or success lost resume.");
                Require(calls.Deleted==!new[]{"duplicate","nul","attribute-size","initialize"}.Contains(failure),"Fixture attribute cleanup coverage changed.");
                if(new[]{"duplicate","nul","create","partial-create","create-throw","membership-error","resume-error"}.Contains(failure))Require(caught.InnerExceptions.OfType<Win32Exception>().Any(error=>error.NativeErrorCode==5),"Child native error lost.");
                if(failure=="rollback")Require(caught.InnerExceptions.Count==2 && caught.InnerExceptions[0].Message=="birth" && caught.InnerExceptions[1].Message=="rollback","Rollback hid initiating failure.");
            }
        }
        public static int Main(string[] args) {
            string phase="arguments";Options o=null;
            try {
                Require(OperatingSystem.IsWindows(),"Windows fixture required.");o=Parse(args);phase="product";string runtimeDirectory=VerifyProduct(Environment.ProcessPath,o.Manifest,o.ManifestHash);
                Require(String.Equals(Path.GetFullPath(runtimeDirectory).TrimEnd('\\'),Path.GetFullPath(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory()).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase),"Fixture loaded an unbound runtime directory.");
                phase="identity";Require(ParentPid()==o.Parent,"Fixture parent mismatch.");bool member;Native.Check(Native.IsProcessInJob(Native.GetCurrentProcess(),IntPtr.Zero,out member));Require(member,"Fixture outside supervision.");
                Directory.CreateDirectory(o.Directory);Marker(o);phase="children";
                switch(o.Mode) {
                    case "root":case "late":
                        if(o.Mode=="late"){var clock=Stopwatch.StartNew();while(!File.Exists(Path.Combine(o.Directory,"go"))){Require(clock.ElapsedMilliseconds<10000,"Fixture signal absent.");Thread.Sleep(10);}}
                        Spawn(o,"child");using(var f=new FileStream(Path.Combine(o.Directory,"root-done"),FileMode.CreateNew)){f.Write(Utf8.GetBytes("done"));}break;
                    case "child":Spawn(o,"grandchild");Thread.Sleep(60000);break;
                    case "grandchild":case "hold":Thread.Sleep(60000);break;
                    case "fanout":for(int i=0;i<3;i++)Spawn(o,"hold");using(var f=new FileStream(Path.Combine(o.Directory,"fanout-done"),FileMode.CreateNew)){f.WriteByte(1);}break;
                    case "exit":WriteBytes(-11,Utf8.GetBytes(o.Echo+"\n"));break;
                    case "output":
                        var buffer=new byte[8192];Array.Fill(buffer,(byte)'x');for(int i=0;i<8192;i++)WriteBytes(-11,buffer);WriteBytes(-11,new[]{(byte)'x'});
                        Array.Fill(buffer,(byte)'e');for(int i=0;i<8;i++)WriteBytes(-12,buffer);WriteBytes(-12,new[]{(byte)'e'});break;
                    case "breakaway":Spawn(o,"hold",true);using(var f=new FileStream(Path.Combine(o.Directory,"breakaway-denied"),FileMode.CreateNew)){f.WriteByte(1);}break;
                    case "early-error-output":var diagnostic=new byte[131073];Array.Fill(diagnostic,(byte)'e');WriteBytes(-12,diagnostic);throw new InvalidOperationException("Synthetic fixture failure.");
                    case "early-error":throw new InvalidOperationException("Synthetic fixture failure.");
                }
                return 0;
            } catch(Exception error) {
                int? nativeCode=error is Win32Exception native?(int?)native.NativeErrorCode:null;
                try{WriteBytes(-12,Utf8.GetBytes("fixture-failure phase="+phase+" type="+error.GetType().Name+" native-error="+(nativeCode?.ToString(CultureInfo.InvariantCulture)??"none")+"\n"));}catch{}
                if(o!=null)try{string diagnostics=Path.Combine(o.Directory,"launch-diagnostics");Directory.CreateDirectory(diagnostics);WriteNew(Path.Combine(diagnostics,"failure-"+Environment.ProcessId+".json"),new{phase,runId=o.Run,mode=o.Mode,type=error.GetType().Name,nativeErrorCode=nativeCode,innerErrors=error is AggregateException aggregate?aggregate.InnerExceptions.Take(16).Select(e=>new{type=e.GetType().Name,nativeErrorCode=e is Win32Exception win?(int?)win.NativeErrorCode:null}).ToArray():null});}catch{}
                return 1;
            }
        }
        public static void OfflineContracts() {
            ChildContracts();
            string directory=@"C:\space path\é😀",profile=Path.Combine(directory,"profile"),run=new string('a',32),manifest=@"C:\product\fixture.product.json",hash=new string('b',64);
            string echo="spaces quote\" trailing\\ unicode-é😀\n";var valid=Arguments("root",directory,profile,run,123,manifest,hash,echo);var parsed=Parse(valid);
            Require(parsed.Directory==directory && parsed.Profile==profile && parsed.Echo==echo && parsed.Manifest==manifest && parsed.ManifestHash==hash,"Fixture argv contents changed.");
            var invalid=new List<string[]> {valid.Concat(new[]{valid[0]}).ToArray(),valid.Take(7).ToArray(),valid.Concat(new[]{"--unknown=x"}).ToArray()};
            foreach(var entry in new[]{(0,"--mode=other"),(1,"--directory-b64=YR=="),(1,"--directory-b64=/w=="),(2,"--user-data-dir=C:\\other"),(3,"--fixture-run="+new string('A',32)),(4,"--parent-pid=0"),(5,"--product-b64=cmVsYXRpdmU="),(6,"--product-sha256=no"),(7,"--echo-b64=%%%")}) {var bad=(string[])valid.Clone();bad[entry.Item1]=entry.Item2;invalid.Add(bad);}
            foreach(var bad in invalid){bool rejected=false;try{Parse(bad);}catch{rejected=true;}Require(rejected,"Malformed fixture arguments accepted.");}
            Require(Encode(Decode(Encode(echo)))==Encode(echo),"Fixture UTF-8 round trip changed.");
            byte[] payload=Utf8.GetBytes("partial-\u00e9\ud83d\ude00");int consumed=0,calls=0;
            WriteBuffer(new IntPtr(7),payload,delegate(IntPtr handle,IntPtr bytes,uint count,out uint written){Require(handle==new IntPtr(7) && count==payload.Length-consumed,"Partial-write offset/count changed.");written=Math.Min(count,(uint)(++calls));for(int i=0;i<written;i++)Require(Marshal.ReadByte(bytes,i)==payload[consumed+i],"Partial-write contents changed.");consumed+=(int)written;return true;});
            Require(consumed==payload.Length && calls>1,"Partial writes were not completed.");
            foreach(string failure in new[]{"zero","oversize","native"}){bool rejected=false;int? code=null;try{WriteBuffer(new IntPtr(7),payload,delegate(IntPtr handle,IntPtr bytes,uint count,out uint written){written=failure=="oversize"?count+1:0;if(failure=="native"){Marshal.SetLastPInvokeError(5);return false;}return true;});}catch(Win32Exception error){rejected=true;code=error.NativeErrorCode;}catch(InvalidOperationException){rejected=true;}Require(rejected && (failure!="native"||code==5),"Write failure or original native error hidden.");}
        }
    }
}
