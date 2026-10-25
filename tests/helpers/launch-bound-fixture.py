"""Disposable native contract fixture. No network, credentials, or existing processes."""
import argparse,json,os,subprocess,sys,time,ctypes
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8');sys.stderr.reconfigure(encoding='utf-8')
p=argparse.ArgumentParser();p.add_argument('--mode',required=True);p.add_argument('--directory',required=True);p.add_argument('--user-data-dir',required=True);p.add_argument('--echo',default='');a=p.parse_args()
d=Path(a.directory);d.mkdir(parents=True,exist_ok=True)
created=None
if os.name=='nt':
 kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.GetCurrentProcess.restype=ctypes.c_void_p
 kernel.GetProcessTimes.argtypes=[ctypes.c_void_p]+[ctypes.POINTER(ctypes.c_ulonglong)]*4
 times=[ctypes.c_ulonglong()for _ in range(4)]
 if not kernel.GetProcessTimes(kernel.GetCurrentProcess(),*[ctypes.byref(t)for t in times]):raise ctypes.WinError(ctypes.get_last_error())
 created=str(times[0].value)
marker=d/(a.mode+('-'+str(os.getpid())if a.mode=='hold'else'')+'.json')
temporary=d/(marker.name+'.'+str(os.getpid())+'.tmp')
temporary.write_text(json.dumps({'pid':os.getpid(),'parent':os.getppid(),'creationFileTime':created,'echo':a.echo}),encoding='utf-8');temporary.replace(marker)
def spawn(mode,flags=0):
 return subprocess.Popen([sys.executable,__file__,'--mode',mode,'--directory',str(d),'--user-data-dir',a.user_data_dir],creationflags=flags)
if a.mode in ['root','late']:
 if a.mode=='late':
  end=time.monotonic()+10
  while not(d/'go').exists()and time.monotonic()<end:time.sleep(.01)
  if not(d/'go').exists():raise RuntimeError('fixture signal absent')
 spawn('child');(d/'root-done').write_text('done',encoding='utf-8')
elif a.mode=='fanout':
 for _ in range(40):spawn('hold')
 (d/'fanout-done').write_text('done',encoding='utf-8')
elif a.mode=='child':spawn('grandchild');time.sleep(60)
elif a.mode in ['grandchild','hold']:time.sleep(60)
elif a.mode=='output':
 sys.stdout.buffer.write(b'x'*(64*1024*1024+1));sys.stdout.buffer.flush();sys.stderr.buffer.write(b'e'*(64*1024+1));sys.stderr.buffer.flush()
elif a.mode=='breakaway':
 try:
  escaped=spawn('hold',0x01000000)
 except OSError as error:
  if getattr(error,'winerror',None)!=5:raise
  (d/'breakaway-denied').write_text('denied',encoding='utf-8')
 else:
  # Unexpected permission is a failed control, never a license to leave an escaped process.
  escaped.terminate();escaped.wait(timeout=5);raise RuntimeError('breakaway unexpectedly permitted')
elif a.mode=='exit':print(a.echo)
else:raise RuntimeError('unknown fixture mode')
