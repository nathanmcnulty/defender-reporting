// Read-only native test observer. It cannot terminate or assign any process.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LaunchBoundTests {
    public sealed class ExitObserver : IDisposable {
        readonly List<SafeWaitHandle> handles = new List<SafeWaitHandle>();
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeWaitHandle process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(SafeWaitHandle process,uint milliseconds);
        public ExitObserver(int[] pids,string[] creations) {
            if(pids==null || creations==null || pids.Length!=creations.Length || pids.Length<1 || pids.Length>128) throw new ArgumentException("Invalid identities.");
            try {
                for(int i=0;i<pids.Length;i++) {
                    long expected; if(pids[i]<=0 || !long.TryParse(creations[i],NumberStyles.None,CultureInfo.InvariantCulture,out expected) || expected<=0) throw new ArgumentException("Invalid identity.");
                    var handle=new SafeWaitHandle(OpenProcess(0x00101000,false,pids[i]),true); handles.Add(handle);
                    if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    long created,exit,kernel,user; if(!GetProcessTimes(handle,out created,out exit,out kernel,out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if(created!=expected || WaitForSingleObject(handle,0)!=258) throw new InvalidOperationException("Fixture identity is not live/matching.");
                }
            } catch { Dispose(); throw; }
        }
        public bool Wait(int milliseconds) {
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
