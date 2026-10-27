// Explicit synthetic control only; the read-only exit observer never terminates a process.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace LaunchBound {
    public sealed class OwnerCrashContext {
        public ActorIdentity Owner,Bootstrap,Node;
        public string RunId,ProfileKey,SessionNonce,BridgeNonce;
    }
    public static class OwnerCrash {
        static void Require(bool value,string message){if(!value)throw new InvalidOperationException(message);}
        static bool Canonical(string value,int length){return value!=null && value.Length==length && value.All(ch=>ch>='a'&&ch<='f'||ch>='0'&&ch<='9');}
        static T Query<T>(int kind)where T:struct{int size=Marshal.SizeOf<T>();IntPtr buffer=Marshal.AllocHGlobal(size);try{Native.Check(Native.QueryCurrentJob(IntPtr.Zero,kind,buffer,size,IntPtr.Zero));return Marshal.PtrToStructure<T>(buffer);}finally{Marshal.FreeHGlobal(buffer);}}
        static int[] Pids(){
            for(int capacity=32;capacity<=32768;capacity*=2){int size=checked(8+IntPtr.Size*capacity);IntPtr buffer=Marshal.AllocHGlobal(size);try{
                if(!Native.QueryCurrentJob(IntPtr.Zero,3,buffer,size,IntPtr.Zero)){int error=Marshal.GetLastPInvokeError();if(error==234)continue;throw new Win32Exception(error);}
                int assigned=Marshal.ReadInt32(buffer),count=Marshal.ReadInt32(buffer,4);if(count<0||count>capacity||assigned!=count)continue;
                var ids=new int[count];for(int i=0;i<count;i++)ids[i]=checked((int)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64());
                Require(ids.All(pid=>pid>0) && ids.Distinct().Count()==ids.Length,"Crash control job census invalid.");return ids;
            }finally{Marshal.FreeHGlobal(buffer);}}
            throw new InvalidOperationException("Crash control job census incomplete.");
        }
        public static object Run(string contextPath,string contextSha256){
            Require(OperatingSystem.IsWindows() && Path.IsPathFullyQualified(contextPath) && Canonical(contextSha256,64),"Explicit Windows actor context required.");
            byte[] bytes;using(var file=new FileStream(contextPath,FileMode.Open,FileAccess.Read,FileShare.Read)){Require(file.Length>0 && file.Length<=65536,"Crash context size invalid.");bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);}
            Require(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()==contextSha256,"Crash context changed.");
            var context=JsonSerializer.Deserialize<OwnerCrashContext>(bytes,new JsonSerializerOptions{IncludeFields=true,MaxDepth=8,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow});
            Require(context!=null && Canonical(context.RunId,32) && Canonical(context.ProfileKey,64) && Canonical(context.SessionNonce,64) && Canonical(context.BridgeNonce,64),"Crash context binding invalid.");
            Require(context.Owner!=null && context.Bootstrap!=null && context.Node!=null && context.Owner.ParentPid==context.Bootstrap.Pid && context.Bootstrap.ParentPid==context.Node.Pid && new[]{context.Owner.Pid,context.Bootstrap.Pid,context.Node.Pid,Environment.ProcessId}.Distinct().Count()==4,"Crash actor ancestry invalid.");
            bool member;Native.Check(Native.IsProcessInJob(Native.GetCurrentProcess(),IntPtr.Zero,out member));Require(member,"Crash control outer job required.");
            var limits=Query<Native.Extended>(9);Require(JobOwner.ValidateOuterPolicy(limits.basic.flags,limits.job.ToUInt64(),Query<uint>(4))==2L*1024*1024*1024,"Native crash control policy changed.");
            using(var owner=new KernelHandle(Native.OpenProcess(0x101001,false,context.Owner.Pid)))
            using(var bootstrap=new KernelHandle(Native.OpenProcess(0x1000,false,context.Bootstrap.Pid)))
            using(var node=new KernelHandle(Native.OpenProcess(0x1000,false,context.Node.Pid))){
                Native.Check(!owner.IsInvalid && !bootstrap.IsInvalid && !node.IsInvalid);
                var actualOwner=ActorIdentity.Read(owner.DangerousGetHandle());var actualBootstrap=ActorIdentity.Read(bootstrap.DangerousGetHandle());var actualNode=ActorIdentity.Read(node.DangerousGetHandle());
                Require(ActorIdentity.Same(context.Owner,actualOwner) && ActorIdentity.Same(context.Bootstrap,actualBootstrap) && ActorIdentity.Same(context.Node,actualNode),"Crash original actor identity mismatch.");
                Require(String.Equals(actualOwner.ImagePath,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase) && String.Equals(actualBootstrap.ImagePath,Environment.ProcessPath,StringComparison.OrdinalIgnoreCase) && Path.GetFileName(actualNode.ImagePath).Equals("node.exe",StringComparison.OrdinalIgnoreCase),"Crash actor image invalid.");
                var pids=Pids();Require(pids.Contains(actualOwner.Pid) && pids.Contains(actualBootstrap.Pid) && pids.Contains(actualNode.Pid) && pids.Contains(Environment.ProcessId),"Crash actor outside current supervised family.");
                uint before=Native.WaitForSingleObject(owner,0);if(before==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastPInvokeError());Require(before==258,"Crash owner was not live.");
                Native.Check(Native.TerminateProcess(owner,125));uint waited=Native.WaitForSingleObject(owner,5000);if(waited==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastPInvokeError());Require(waited==0,"Crash original owner exit unconfirmed.");
                uint code;Native.Check(Native.GetExitCodeProcess(owner,out code));Require(code==125,"Crash original owner exit code changed.");
                return new{ContextSha256=contextSha256,context.RunId,context.ProfileKey,context.SessionNonce,context.BridgeNonce,Owner=actualOwner,Bootstrap=actualBootstrap,Node=actualNode,OriginalHandleExitObserved=true,ExitCode=code,OuterPolicyConfirmed=true};
            }
        }
    }
}
