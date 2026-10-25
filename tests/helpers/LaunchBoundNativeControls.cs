// Compiled together with the engine ONLY by the explicitly selected native control.
// Internal fault injection cannot be requested through the production owner protocol.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
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
        sealed class QueryFault : NativeCalls {
            internal bool Bad,Delay,Negative;
            internal override void BeforeQuery() { if(Delay) Thread.Sleep(30); if(Bad) throw new InvalidOperationException("Synthetic query fault."); }
            internal override void Counters(ref long ws,ref long privateBytes) { if(Negative) privateBytes=-1; }
        }
        static void Require(bool value,string label) { if(!value) throw new InvalidOperationException(label); }
        static void WaitFile(string dir,string name) {
            var clock=Stopwatch.StartNew(); while(!File.Exists(Path.Combine(dir,name))) { if(clock.ElapsedMilliseconds>=3000) throw new TimeoutException("Fixture not ready."); Thread.Sleep(10); }
        }
        static string[] Arguments(string script,string mode,string dir,string profile,string echo="") { return new[]{script,"--mode",mode,"--directory",dir,"--user-data-dir="+profile,"--echo",echo}; }
        public static string[] Run(string python,string script,string directory,int neighborPid) {
            var results=new List<string>(); Directory.CreateDirectory(directory);
            foreach(string mode in new[]{"root","late"}) {
                string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile"); Directory.CreateDirectory(profile);
                using(var owner=mode=="root"?new JobOwner(Guid.NewGuid().ToString("N"),profile,new FirstCensus(dir)):new JobOwner(Guid.NewGuid().ToString("N"),profile)) {
                    var proof=owner.Start(python,Arguments(script,mode,dir,profile),profile);
                    Require(!owner.Contains(neighborPid),"Neighbor was assigned.");
                    if(mode=="late") { File.WriteAllText(Path.Combine(dir,"go"),"go"); WaitFile(dir,"grandchild.json"); WaitFile(dir,"root-done"); Thread.Sleep(100); proof=owner.Query(5000); }
                    Require(proof.ExitCode==0 && proof.ActiveProcesses>=2 && !proof.Terminal && proof.WorkingSetBytes>0 && proof.PrivateBytes>0,"Root-exit descendants lost.");
                    Require(!proof.Pids.Contains(Process.GetCurrentProcess().Id),"Owner counted as browser.");
                    var stopped=owner.Stop(5000); Require(stopped.Confirmed && stopped.Forced && stopped.Pids.Length==0 && stopped.StreamsComplete,"Job did not complete.");
                    Require(owner.Stop(5000).Confirmed,"Repeated completion failed."); results.Add(mode+":contained-descendants-and-zero");
                }
            }
            {
                string dir=Path.Combine(directory,"assignment"),profile=Path.Combine(dir,"profile"); Directory.CreateDirectory(profile); var faults=new AssignmentFailure();
                var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,faults); bool threw=false;
                try { owner.Start(python,Arguments(script,"exit",dir,profile),profile); } catch { threw=true; }
                Require(threw && owner.Setup.Created && !owner.Setup.Assigned && !owner.Setup.Resumed && !File.Exists(Path.Combine(dir,"exit.json")) && !owner.RollbackContained,"Assignment failure resumed or hid rollback failure.");
                owner.Dispose(); Require(faults.Terminations==2 && faults.Waits==2 && owner.RollbackContained,"Dispose did not retry suspended retained root."); owner.Dispose(); results.Add("assignment:first-rollback-failed-dispose-retried-no-resume");
            }
            {
                string dir=Path.Combine(directory,"fanout"),profile=Path.Combine(dir,"profile"); Directory.CreateDirectory(profile);
                using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile)) {
                    owner.Start(python,Arguments(script,"fanout",dir,profile),profile); WaitFile(dir,"fanout-done"); Thread.Sleep(200);
                    var proof=owner.Query(5000); Require(proof.ActiveProcesses>=40 && proof.Pids.Length>=40,"PID buffer growth lost members.");
                    Require(owner.Stop(5000).Confirmed,"Fanout did not complete."); results.Add("fanout:grow-pid-buffer-and-zero");
                }
            }
            foreach(string fault in new[]{"late-query","query-error","negative-memory"}) {
                string dir=Path.Combine(directory,fault),profile=Path.Combine(dir,"profile"); Directory.CreateDirectory(profile); var faults=new QueryFault();
                using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile,faults)) {
                    owner.Start(python,Arguments(script,fault=="late-query"?"exit":"hold",dir,profile),profile);
                    if(fault=="late-query") { owner.Stop(5000); faults.Delay=true; } else if(fault=="query-error") faults.Bad=true; else faults.Negative=true;
                    bool threw=false; try { owner.Query(fault=="late-query"?5:5000); } catch { threw=true; }
                    Require(threw,"Unknown/late query became success.");
                    bool confirmed=false; try { confirmed=owner.Stop(5000).Confirmed; } catch { }
                    Require(!confirmed,"Failed query state reset."); results.Add(fault+":unconfirmed");
                }
            }
            foreach(string mode in new[]{"exit","output","breakaway"}) {
                string dir=Path.Combine(directory,mode),profile=Path.Combine(dir,"profile"); Directory.CreateDirectory(profile);
                using(var owner=new JobOwner(Guid.NewGuid().ToString("N"),profile)) {
                    string echo="spaces quote\" trailing\\ unicode-é";
                    var captured=owner.RunCaptured(python,Arguments(script,mode,dir,profile,echo),profile,15000);
                    Require(captured.Started && !captured.TimedOut && captured.Completion.Confirmed && captured.Completion.StreamsComplete,"Capture incomplete.");
                    Require(captured.ExitCode==0,"Fixture exit failed.");
                    if(mode=="exit") Require(captured.Stdout.Text.Trim()==echo,"Native argv quoting failed.");
                    if(mode=="output") Require(captured.Stdout.Bytes==64*1024*1024+1 && captured.Stderr.Bytes==64*1024+1 && captured.Stdout.Truncated && captured.Stderr.Truncated && Encoding.UTF8.GetByteCount(captured.Stdout.Text)==64*1024*1024 && Encoding.UTF8.GetByteCount(captured.Stderr.Text)==64*1024,"Bounded drains incorrect.");
                    if(mode=="breakaway") Require(File.Exists(Path.Combine(dir,"breakaway-denied")),"Breakaway not rejected.");
                    results.Add(mode+":capture-zero");
                }
            }
            return results.ToArray();
        }
    }
}
