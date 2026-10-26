// Read-only fixture ledger. Never grants assignment or termination authority.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace LaunchBoundTests {
    public sealed class MemberIdentity {
        public int Pid,ParentPid,NativeErrorCode;
        public string CreationFileTime,ImagePath,State="unreadable",Membership="not-queried";
        public bool Live;
    }
    public sealed class ExitObserver : IDisposable {
        readonly List<SafeWaitHandle> handles = new List<SafeWaitHandle>();
        public MemberIdentity[] Members { get; private set; }
        [StructLayout(LayoutKind.Sequential)] struct Basic { public IntPtr exit,peb,affinity,priority,pid,parent; }
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeWaitHandle process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(SafeWaitHandle process,uint flags,StringBuilder image,ref uint size);
        [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(SafeWaitHandle process,int kind,out Basic value,int size,out int returned);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(SafeWaitHandle process,uint milliseconds);
        public ExitObserver(int[] pids,string[] creations) : this(pids,creations,null) { }
        public ExitObserver(int[] pids,string[] creations,Func<IntPtr,bool> membership) {
            if(pids==null || creations==null || pids.Length!=creations.Length || pids.Length<1 || pids.Length>128 || new HashSet<int>(pids).Count!=pids.Length) throw new ArgumentException("Invalid identities.");
            Members=new MemberIdentity[pids.Length];
            try {
                for(int i=0;i<pids.Length;i++) {
                    var item=new MemberIdentity{Pid=pids[i]};Members[i]=item;
                    try {
                        if(pids[i]<=0) throw new ArgumentException("Invalid PID.");
                        var handle=new SafeWaitHandle(OpenProcess(0x00101000,false,pids[i]),true); handles.Add(handle);
                        if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                        long created,exit,kernel,user; if(!GetProcessTimes(handle,out created,out exit,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        item.CreationFileTime=created.ToString(CultureInfo.InvariantCulture);
                        var image=new StringBuilder(32768);uint length=(uint)image.Capacity;
                        if(!QueryFullProcessImageNameW(handle,0,image,ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());item.ImagePath=image.ToString();
                        Basic basic;int returned;int status=NtQueryInformationProcess(handle,0,out basic,Marshal.SizeOf<Basic>(),out returned);
                        if(status!=0 || returned!=Marshal.SizeOf<Basic>()) throw new InvalidOperationException("Parent identity unreadable.");item.ParentPid=checked((int)basic.parent.ToInt64());
                        item.Membership=membership==null?"bound-query-required":membership(handle.DangerousGetHandle())?"member":"not-member";
                        uint wait=WaitForSingleObject(handle,0);if(wait!=0 && wait!=258) throw new Win32Exception(Marshal.GetLastWin32Error());item.Live=wait==258;
                        item.State=!item.Live?"exited":String.IsNullOrEmpty(creations[i])?"unclassified":item.CreationFileTime==creations[i]?"identified":"reused";
                    } catch(Win32Exception error) { item.NativeErrorCode=error.NativeErrorCode; }
                    catch { item.State="unreadable"; }
                }
            } catch { Dispose(); throw; }
        }
        public bool Ready {
            get { foreach(var item in Members) if(item.State!="identified" || !item.Live || item.Membership=="not-member") return false; return handles.Count==Members.Length; }
        }
        public bool AllLive() {
            if(!Ready) return false;
            foreach(var h in handles) if(WaitForSingleObject(h,0)!=258) return false;
            return true;
        }
        public bool Wait(int milliseconds) {
            if(!Ready) return false;
            var clock=Stopwatch.StartNew();
            foreach(var h in handles) {
                int remaining=Math.Max(0,milliseconds-(int)clock.ElapsedMilliseconds);
                if(WaitForSingleObject(h,(uint)remaining)!=0) return false;
            }
            return clock.ElapsedMilliseconds<milliseconds;
        }
        public void Dispose() { foreach(var h in handles)h.Dispose(); handles.Clear(); }
    }
}
