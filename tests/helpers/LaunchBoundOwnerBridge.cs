// One fixed real PowerShell owner behind Node's private pipes. No job is created here.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace LaunchBound {
    public static class OwnerBridge {
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int which);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr duplicate,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll",EntryPoint="WaitForSingleObject",SetLastError=true)] static extern uint WaitRaw(IntPtr process,uint milliseconds);
        [DllImport("kernel32.dll",EntryPoint="TerminateProcess",SetLastError=true)] static extern bool TerminateRaw(IntPtr process,uint code);
        [DllImport("kernel32.dll",EntryPoint="GetExitCodeProcess",SetLastError=true)] static extern bool ExitRaw(IntPtr process,out uint code);
        static bool Handle(IntPtr value){return value!=IntPtr.Zero && value!=new IntPtr(-1);}
        static bool Pipe(IntPtr value){uint kind=GetFileType(value);int error=Marshal.GetLastPInvokeError();if(kind==0 && error!=0)throw new Win32Exception(error);return kind==3;}
        static void Require(bool value,string message){if(!value)throw new InvalidOperationException(message);}
        static void Attempt(List<Exception> errors,Action action){try{action();}catch(Exception error){errors.Add(error);}}
        internal class Calls {
            internal virtual void Paths(string runtime,string script){Require(OperatingSystem.IsWindows() && Path.IsPathFullyQualified(runtime) && Path.GetFileName(runtime).Equals("pwsh.exe",StringComparison.OrdinalIgnoreCase) && File.Exists(runtime) && Path.IsPathFullyQualified(script) && Path.GetFileName(script)=="Invoke-LaunchBoundOwner.ps1" && File.Exists(script),"Fixed PowerShell owner required.");}
            internal virtual IntPtr Duplicate(int slot){
                IntPtr original=GetStdHandle(slot),copy=IntPtr.Zero;Require(Handle(original) && Pipe(original),"Private owner pipe missing.");
                try{Native.Check(DuplicateHandle(Native.GetCurrentProcess(),original,Native.GetCurrentProcess(),out copy,0,true,2));uint flags;Native.Check(Native.GetHandleInformation(copy,out flags));Require(Handle(copy) && copy!=original && Pipe(copy) && (flags&1)!=0,"Owner pipe duplicate invalid.");return copy;}
                catch(Exception failure){var errors=new List<Exception>{failure};if(Handle(copy) && copy!=original)Attempt(errors,()=>Close(copy));if(errors.Count>1)throw new AggregateException("Owner pipe validation/cleanup failed.",errors);throw;}
            }
            internal virtual void Initialize(IntPtr list,ref UIntPtr size){Native.Check(Native.InitializeProcThreadAttributeList(list,1,0,ref size));}
            internal virtual void Size(ref UIntPtr size){bool returned=Native.InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);int error=Marshal.GetLastPInvokeError();if(!returned && error!=122)throw new Win32Exception(error);Require(!returned && size.ToUInt64()>0 && size.ToUInt64()<=65536,"Owner handle-list size invalid.");}
            internal virtual void Set(IntPtr list,IntPtr handles){Native.Check(Native.UpdateProcThreadAttribute(list,0,new UIntPtr(0x20002),handles,new UIntPtr((uint)(3*IntPtr.Size)),IntPtr.Zero,IntPtr.Zero));}
            internal virtual bool Create(string runtime,StringBuilder command,ref Native.SIX startup,out Native.PI child){return Native.CreateProcessW(runtime,command,IntPtr.Zero,IntPtr.Zero,true,0x08080000,IntPtr.Zero,Path.GetDirectoryName(runtime),ref startup,out child);}
            internal virtual ActorIdentity Self(){return ActorIdentity.Read(Native.GetCurrentProcess());}
            internal virtual ActorIdentity Node(int pid){using(var process=new KernelHandle(Native.OpenProcess(0x1000,false,pid))){Native.Check(!process.IsInvalid);return ActorIdentity.Read(process.DangerousGetHandle());}}
            internal virtual ActorIdentity Child(IntPtr process){return ActorIdentity.Read(process);}
            internal virtual bool Member(IntPtr process){bool member;Native.Check(Native.IsProcessInJob(process,IntPtr.Zero,out member));return member;}
            internal virtual void Prefix(string nonce,ActorIdentity owner,ActorIdentity self,ActorIdentity node){Console.Out.WriteLine(JsonSerializer.Serialize(new{v=1,bridge=true,nonce,owner,bootstrap=self,node},new JsonSerializerOptions{IncludeFields=true}));Console.Out.Flush();}
            internal virtual uint Wait(IntPtr process,uint milliseconds){return WaitRaw(process,milliseconds);}
            internal virtual bool Terminate(IntPtr process){return TerminateRaw(process,125);}
            internal virtual uint Exit(IntPtr process){uint code;Native.Check(ExitRaw(process,out code));return code;}
            internal virtual void Delete(IntPtr list){Native.DeleteProcThreadAttributeList(list);}
            internal virtual void Close(IntPtr value){Native.Check(Native.CloseHandle(value));}
        }
        public static int Run(string ownerScript){return Run(Environment.ProcessPath,ownerScript,new Calls());}
        internal static int Run(string runtime,string ownerScript,Calls calls){
            calls.Paths(runtime,ownerScript);var errors=new List<Exception>();var duplicates=new List<IntPtr>();
            IntPtr list=IntPtr.Zero,handles=IntPtr.Zero;bool initialized=false,childExited=false;Native.PI child=default;int exit=-1;
            try{
                foreach(int slot in new[]{-10,-11,-12}){IntPtr copy=calls.Duplicate(slot);Require(Handle(copy) && !duplicates.Contains(copy),"Owner inherited handle set invalid.");duplicates.Add(copy);}
                UIntPtr size=UIntPtr.Zero;calls.Size(ref size);list=Marshal.AllocHGlobal(checked((int)size.ToUInt64()));calls.Initialize(list,ref size);initialized=true;
                handles=Marshal.AllocHGlobal(3*IntPtr.Size);for(int i=0;i<3;i++)Marshal.WriteIntPtr(handles,i*IntPtr.Size,duplicates[i]);calls.Set(list,handles);
                string nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
                string[] arguments={"-NoProfile","-NonInteractive","-File",ownerScript,"-BridgeNonce",nonce};
                string command=JobOwner.Quote(runtime)+" "+String.Join(" ",arguments.Select(JobOwner.Quote));Require(command.Length<32767,"Owner command too long.");
                var startup=new Native.SIX{startup=new Native.SI{cb=Marshal.SizeOf<Native.SIX>(),flags=0x100,input=duplicates[0],output=duplicates[1],error=duplicates[2]},attributes=list};
                bool created=calls.Create(runtime,new StringBuilder(command),ref startup,out child);int nativeError=Marshal.GetLastPInvokeError();if(!created)throw new Win32Exception(nativeError);
                Require(Handle(child.process) && Handle(child.thread) && child.pid>0,"Owner original handles missing.");
                var self=calls.Self();var node=calls.Node(self.ParentPid);var owner=calls.Child(child.process);
                Require(self.ParentPid==node.Pid && owner.Pid==child.pid && owner.ParentPid==self.Pid && String.Equals(owner.ImagePath,runtime,StringComparison.OrdinalIgnoreCase) && String.Equals(self.ImagePath,runtime,StringComparison.OrdinalIgnoreCase) && calls.Member(child.process),"Owner creator identity or supervision unknown.");
                foreach(IntPtr copy in duplicates.ToArray()){calls.Close(copy);duplicates.Remove(copy);}
                // The real owner waits for a client activation ACK before emitting
                // protocol bytes or creating a JobOwner. A running gate also exits
                // on pipe EOF if the bootstrap dies during startup.
                calls.Prefix(nonce,owner,self,node);
                uint waited=calls.Wait(child.process,UInt32.MaxValue);if(waited==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastPInvokeError());Require(waited==0,"Owner original-handle wait unknown.");childExited=true;exit=unchecked((int)calls.Exit(child.process));
            }catch(Exception failure){
                errors.Add(failure);
                if(Handle(child.process) && !childExited){
                    bool ended=false;Attempt(errors,()=>{uint wait=calls.Wait(child.process,0);if(wait==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastPInvokeError());ended=wait==0;});
                    if(!ended)Attempt(errors,()=>Native.Check(calls.Terminate(child.process)));
                    Attempt(errors,()=>{uint wait=calls.Wait(child.process,5000);if(wait==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastPInvokeError());Require(wait==0,"Owner original-handle rollback unconfirmed.");});
                }
            }finally{
                if(initialized)Attempt(errors,()=>calls.Delete(list));if(Handle(list))Marshal.FreeHGlobal(list);if(Handle(handles))Marshal.FreeHGlobal(handles);
                foreach(IntPtr copy in duplicates)Attempt(errors,()=>calls.Close(copy));
                if(Handle(child.thread))Attempt(errors,()=>calls.Close(child.thread));if(Handle(child.process))Attempt(errors,()=>calls.Close(child.process));
            }
            if(errors.Count==1)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(errors[0]).Throw();if(errors.Count>1)throw new AggregateException("Owner bridge launch/cleanup failed.",errors);return exit;
        }
        sealed class Fault : Calls {
            internal string Failure;internal bool PrefixSent,Terminated,Deleted,CloseRetried;internal readonly List<IntPtr> Closed=new List<IntPtr>();
            internal override void Paths(string runtime,string script){}
            static ActorIdentity Actor(int pid,int parent,string image){return new ActorIdentity{Pid=pid,ParentPid=parent,CreationFileTime="1",ImagePath=image};}
            internal override IntPtr Duplicate(int slot){if(Failure=="duplicate" && slot==-11)throw new Win32Exception(5);return new IntPtr(-slot+100);}
            internal override void Size(ref UIntPtr size){size=new UIntPtr(64);}
            internal override void Initialize(IntPtr list,ref UIntPtr size){if(Failure=="initialize")throw new Win32Exception(5);}
            internal override void Set(IntPtr list,IntPtr handles){if(Failure=="set")throw new Win32Exception(5);Require(Marshal.ReadIntPtr(handles)==new IntPtr(110) && Marshal.ReadIntPtr(handles,IntPtr.Size)==new IntPtr(111) && Marshal.ReadIntPtr(handles,2*IntPtr.Size)==new IntPtr(112),"Bridge inherited handle order changed.");}
            internal override bool Create(string runtime,StringBuilder command,ref Native.SIX startup,out Native.PI child){
                Require(startup.startup.flags==0x100 && startup.startup.cb==Marshal.SizeOf<Native.SIX>() && command.ToString().Contains("-BridgeNonce"),"Bridge startup contract changed.");
                child=new Native.PI{process=Failure=="missing-process"?IntPtr.Zero:new IntPtr(301),thread=Failure=="missing-thread"?IntPtr.Zero:new IntPtr(302),pid=11};
                if(Failure=="create-throw")throw new Win32Exception(5);Marshal.SetLastPInvokeError(5);return Failure!="partial-create";
            }
            internal override ActorIdentity Self(){return Actor(10,9,@"C:\pwsh.exe");}
            internal override ActorIdentity Node(int pid){return Actor(9,8,@"C:\node.exe");}
            internal override ActorIdentity Child(IntPtr process){if(Failure=="read-identity")throw new Win32Exception(5);return Actor(11,Failure=="identity"?99:10,@"C:\pwsh.exe");}
            internal override bool Member(IntPtr process){return Failure!="membership";}
            internal override void Prefix(string nonce,ActorIdentity owner,ActorIdentity self,ActorIdentity node){Require(nonce.Length==64 && Closed.Contains(new IntPtr(110)) && Closed.Contains(new IntPtr(111)) && Closed.Contains(new IntPtr(112)),"Bridge prefix handle list was not sealed.");if(Failure=="prefix" || Failure=="rollback")throw new Win32Exception(5);PrefixSent=true;}
            internal override uint Wait(IntPtr process,uint milliseconds){if(milliseconds==UInt32.MaxValue)Require(PrefixSent,"Bridge wait began before creator observation.");if(Failure=="wait" && milliseconds==UInt32.MaxValue){Marshal.SetLastPInvokeError(5);return UInt32.MaxValue;}return milliseconds==UInt32.MaxValue || Terminated?0U:258U;}
            internal override bool Terminate(IntPtr process){if(Failure=="rollback"){Marshal.SetLastPInvokeError(5);return false;}Terminated=true;return true;}
            internal override uint Exit(IntPtr process){if(Failure=="exit-code")throw new Win32Exception(5);return 0;}
            internal override void Delete(IntPtr list){Deleted=true;if(Failure=="delete")throw new Win32Exception(5);}
            internal override void Close(IntPtr value){if((Failure=="close-duplicate" && value==new IntPtr(110) || Failure=="close-process" && value==new IntPtr(301)) && !CloseRetried){CloseRetried=true;throw new Win32Exception(5);}Require(!Closed.Contains(value),"Bridge handle closed twice.");Closed.Add(value);}
        }
        public static void OfflineContracts(){
            foreach(string failure in new[]{"none","duplicate","initialize","set","partial-create","create-throw","missing-process","missing-thread","read-identity","identity","membership","prefix","wait","exit-code","delete","close-duplicate","close-process","rollback"}){
                var calls=new Fault{Failure=failure};Exception caught=null;int result=-1;try{result=Run(@"C:\pwsh.exe",@"C:\Invoke-LaunchBoundOwner.ps1",calls);}catch(Exception error){caught=error;}
                Require((caught==null)==(failure=="none"),"Bridge fault became success.");
                if(failure=="none")Require(result==0 && calls.PrefixSent && calls.Closed.Contains(new IntPtr(301)) && calls.Closed.Contains(new IntPtr(302)),"Bridge original-handle completion changed.");
                if(new[]{"partial-create","create-throw","missing-thread","read-identity","identity","membership","prefix","wait","close-duplicate"}.Contains(failure))Require(calls.Terminated && calls.Closed.Contains(new IntPtr(301)),"Bridge failure did not contain original owner.");
                if(failure=="rollback")Require(caught is AggregateException aggregate && aggregate.InnerExceptions.Count>=3,"Bridge rollback errors suppressed.");
                if(caught is Win32Exception native)Require(native.NativeErrorCode==5,"Bridge original native error lost.");
            }
        }
    }
}
