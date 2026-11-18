// TC-009 support. All actions are scoped to one retained process and exact window/control IDs.
// No elevation, deployment command, global input injection, remote code or process termination.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Globalization;
using Microsoft.Win32.SafeHandles;

namespace LexHelperGuiTest {
    [ComImport,Guid("618736E0-3C3D-11CF-810C-00AA00389B71"),InterfaceType(ComInterfaceType.InterfaceIsDual)]
    interface Accessible {
        [DispId(-5000)] object Parent { [return:MarshalAs(UnmanagedType.IDispatch)] get; }
        [DispId(-5001)] int ChildCount { get; }
        [DispId(-5002)] [return:MarshalAs(UnmanagedType.IDispatch)] object Child([In,MarshalAs(UnmanagedType.Struct)] object child);
        [DispId(-5003)] [return:MarshalAs(UnmanagedType.BStr)] string Name([In,MarshalAs(UnmanagedType.Struct)] object child);
        // Preserve HRESULT: S_FALSE means no Value property; S_OK with an empty value
        // is a readable (but possibly wrong) business result, NOT absent capability.
        [DispId(-5004),PreserveSig] int Value([In,MarshalAs(UnmanagedType.Struct)] object child,[MarshalAs(UnmanagedType.BStr)] out string value);
    }
    public sealed class WindowInfo {
        public IntPtr Handle;
        public string Class;
        public string Text;
        public int Id;
        public override string ToString() { return Id + ": " + Class + " " + Text; }
    }
    public sealed class ProcessIdentity {
        public int ProcessId { get; internal set; }
        public string Executable { get; internal set; }
        // Strings intentionally avoid JSON/JavaScript double rounding of 100 ns ticks.
        public string CreationTimeUtcTicks { get; internal set; }
        public string CreationTimeUtc { get; internal set; }
        public string CaptureError { get; internal set; }
    }
    public sealed class CleanupResult {
        public ProcessIdentity Identity { get; internal set; }
        public string State { get; internal set; }
        public string Reason { get; internal set; }
        public int? ExitCode { get; internal set; }
    }
    // Retains the actual CreateProcess/OpenProcess handle, not a later PID lookup.
    // Dispose releases ownership of the handle; it NEVER ends the process lifetime.
    public sealed class OwnedProcess : IDisposable {
        internal SafeProcessHandle NativeHandle;
        public int Id { get; private set; }
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(SafeProcessHandle h,uint ms);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(SafeProcessHandle h,out uint code);
        internal OwnedProcess(IntPtr handle,int pid) { NativeHandle=new SafeProcessHandle(handle,true);Id=pid; }
        public IntPtr Handle { get { return NativeHandle.DangerousGetHandle(); } }
        public bool HasExited { get { return WaitForExit(0); } }
        public bool WaitForExit(int ms) {
            if(ms<0)throw new ArgumentOutOfRangeException(nameof(ms));
            uint result=WaitForSingleObject(NativeHandle,(uint)ms);
            if(result==0)return true;if(result==258)return false;
            throw new InvalidOperationException("Process wait failed: "+Marshal.GetLastWin32Error());
        }
        public int ExitCode { get { uint code;if(!HasExited || !GetExitCodeProcess(NativeHandle,out code))throw new InvalidOperationException("No process exit code");return unchecked((int)code); } }
        public void Dispose() { NativeHandle.Dispose(); }
    }
    public sealed class AccessibilityProbe {
        public bool HeaderAvailable;
        public string HeaderUnavailableReason;
        public string[] HeaderNames=new string[0];
        public bool UnicodeAvailable;
        public string UnicodeUnavailableReason;
        public string[] UnicodeValues=new string[0];
        public string[] ReadableRowNames=new string[0];
    }
    public sealed class Session : IDisposable {
        public OwnedProcess Process { get; private set; }
        public ProcessIdentity OriginalIdentity { get; private set; }
        public IntPtr Main { get; private set; }
        readonly string executable;
        readonly string root;
        delegate bool Callback(IntPtr window, IntPtr argument);
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo {
            public uint Size; public string Reserved,Desktop,Title;
            public uint X,Y,Width,Height,Columns,Rows,Fill,Flags;
            public ushort Show,ReservedSize; public IntPtr ReservedBytes,Input,Output,Error;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr Process,Thread;public uint Pid,Tid;}
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfo startup,out ProcessInfo information);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeProcessHandle process,out long creation,out long exit,out long kernel,out long user);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder name,ref uint size);
        [DllImport("user32.dll",SetLastError=true)] static extern uint WaitForInputIdle(SafeProcessHandle process,uint ms);
        [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
        [StructLayout(LayoutKind.Sequential)] struct GuiInfo {
            public int Size, Flags; public IntPtr Active, Focus, Capture, MenuOwner, MoveSize, Caret; public Rect CaretRect;
        }
        [DllImport("user32.dll")] static extern bool EnumWindows(Callback cb, IntPtr arg);
        [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, Callback cb, IntPtr arg);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr w, StringBuilder b, int n);
        [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr w);
        [DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr w, int id);
        [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr w);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr w);
        [DllImport("user32.dll")] static extern bool IsWindow(IntPtr w);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr w);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr w);
        [DllImport("user32.dll")] static extern IntPtr GetMenu(IntPtr w);
        [DllImport("user32.dll")] static extern uint GetMenuState(IntPtr menu,uint id,uint flags);
        [DllImport("user32.dll", EntryPoint="GetWindowLongW")] static extern int GetWindowLong(IntPtr w, int index);
        [DllImport("user32.dll", SetLastError=true)] static extern bool PostMessage(IntPtr w, uint m, IntPtr a, IntPtr b);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessageTimeout(IntPtr w, uint m, IntPtr a, StringBuilder b, uint flags, uint ms, out IntPtr result);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessageTimeout(IntPtr w, uint m, IntPtr a, string b, uint flags, uint ms, out IntPtr result);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessageTimeout(IntPtr w, uint m, IntPtr a, IntPtr b, uint flags, uint ms, out IntPtr result);
        [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr w, out Rect r);
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr w, out Rect r);
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr w, IntPtr after, int x, int y, int width, int height, uint flags);
        [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr w);
        [DllImport("user32.dll")] static extern bool AdjustWindowRectExForDpi(ref Rect r, uint style, bool menu, uint exStyle, uint dpi);
        [DllImport("user32.dll")] static extern bool GetGUIThreadInfo(uint thread, ref GuiInfo info);
        [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr w,IntPtr dc,uint flags);
        [DllImport("oleacc.dll")] static extern int AccessibleObjectFromWindow(IntPtr w,uint objectId,ref Guid iid,[MarshalAs(UnmanagedType.Interface)] out Accessible accessible);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr library);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindResource(IntPtr library,IntPtr name,IntPtr type);
        [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr library,IntPtr resource);
        [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
        [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr library,IntPtr resource);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int info,out int elevation,int size,out int returned);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

        public Session(string exe,string directory) : this(exe,directory,false) {}
        public Session(string exe, string directory,bool interactive) {
            executable=Path.GetFullPath(exe); root=Path.GetFullPath(directory).TrimEnd('\\')+"\\";
            if (!root.StartsWith(@"D:\temp\aiRunner\opencode\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unsafe test root");
            // wWinMain forwards nCmdShow to Application::run -> ShowWindow. STARTF_USESHOWWINDOW
            // therefore applies to the first show. Default SW_SHOWMINNOACTIVE=7; explicit
            // interactive mode starts SW_SHOWNOACTIVATE=4, never TOPMOST/SetForegroundWindow.
            var startup=new StartupInfo {Size=(uint)Marshal.SizeOf<StartupInfo>(),Flags=1,Show=(ushort)(interactive?4:7)};
            ProcessInfo info;
            if(!CreateProcess(executable,new StringBuilder("\""+executable+"\""),IntPtr.Zero,IntPtr.Zero,false,0,IntPtr.Zero,Path.GetDirectoryName(executable),ref startup,out info))
                throw new InvalidOperationException("CreateProcess failed: "+Marshal.GetLastWin32Error());
            Process=new OwnedProcess(info.Process,(int)info.Pid);
            CloseHandle(info.Thread);
            // No window wait/validation here. Even failed identity capture is retained and
            // reportable; without complete identity, cleanup refuses to send messages.
            OriginalIdentity=CaptureIdentity();
        }
        // Recovery REQUIRES the original exact UTC ticks, never a suite-time lower bound.
        public Session(string exe,string directory,int ownedPid,string originalCreationTimeUtcTicks) {
            executable=Path.GetFullPath(exe);root=Path.GetFullPath(directory).TrimEnd('\\')+"\\";
            if(!root.StartsWith(@"D:\temp\aiRunner\opencode\",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Unsafe test root");
            long ticks;
            if(!long.TryParse(originalCreationTimeUtcTicks,NumberStyles.None,CultureInfo.InvariantCulture,out ticks) || ticks<=0 || ticks>DateTime.MaxValue.Ticks)
                throw new InvalidOperationException("Exact original creation UTC ticks required; legacy records cannot authorize cleanup");
            var handle=OpenProcess(0x00101000,false,ownedPid); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION
            if(handle==IntPtr.Zero)throw new InvalidOperationException("Open recorded process failed: "+Marshal.GetLastWin32Error());
            Process=new OwnedProcess(handle,ownedPid);
            try {
                OriginalIdentity=CaptureIdentity();
                if(OriginalIdentity.CreationTimeUtcTicks!=ticks.ToString(CultureInfo.InvariantCulture))throw new InvalidOperationException("Original process creation time mismatch; no window action allowed");
                Identity();
            } catch {Process.Dispose();throw;}
        }
        ProcessIdentity CaptureIdentity() {
            var identity=new ProcessIdentity {ProcessId=Process.Id,Executable=executable};
            try {
                long creation,exit,kernel,user;
                if(!GetProcessTimes(Process.NativeHandle,out creation,out exit,out kernel,out user))throw new InvalidOperationException("GetProcessTimes failed: "+Marshal.GetLastWin32Error());
                var utc=DateTime.FromFileTimeUtc(creation);
                identity.CreationTimeUtcTicks=utc.Ticks.ToString(CultureInfo.InvariantCulture);
                identity.CreationTimeUtc=utc.ToString("o",CultureInfo.InvariantCulture);
                if(!String.Equals(ImagePath(),executable,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Created executable path mismatch");
            } catch(Exception e) {identity.CaptureError=e.Message;}
            return identity;
        }
        string ImagePath() {
            var name=new StringBuilder(32768);uint size=(uint)name.Capacity;
            if(!QueryFullProcessImageName(Process.NativeHandle,0,name,ref size))throw new InvalidOperationException("Process image query failed: "+Marshal.GetLastWin32Error());
            return Path.GetFullPath(name.ToString());
        }
        public void InitializeWindow() { InitializeWindow("LexHelper.MainWindow",15000); }
        // The expected-class/timeout overload is a support-only fixture seam, not a product hook.
        public void InitializeWindow(string expectedClass,int milliseconds) {
            if(milliseconds<1 || milliseconds>60000)throw new ArgumentOutOfRangeException(nameof(milliseconds));
            Identity();var timer=Stopwatch.StartNew();
            uint idle=WaitForInputIdle(Process.NativeHandle,(uint)milliseconds);
            if(idle!=0)throw new InvalidOperationException("Input idle failed/timeout: "+idle);
            do {
                foreach(var w in Windows())if(w.Class==expectedClass) {Main=w.Handle;return;}
                if(Process.WaitForExit(25))throw new InvalidOperationException("Process exited during window initialization");
            }while(timer.ElapsedMilliseconds<milliseconds);
            throw new InvalidOperationException("Owned main window missing: "+expectedClass);
        }
        void Identity() {
            if(OriginalIdentity.CaptureError!=null || OriginalIdentity.CreationTimeUtcTicks==null)throw new InvalidOperationException("Original identity incomplete: "+OriginalIdentity.CaptureError);
            long creation,exit,kernel,user;
            if(Process.HasExited || !GetProcessTimes(Process.NativeHandle,out creation,out exit,out kernel,out user) ||
                DateTime.FromFileTimeUtc(creation).Ticks.ToString(CultureInfo.InvariantCulture)!=OriginalIdentity.CreationTimeUtcTicks ||
                !String.Equals(ImagePath(),executable,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Owned process identity lost");
        }
        void Own(IntPtr w) {
            Identity(); uint pid; GetWindowThreadProcessId(w,out pid);
            if(w==IntPtr.Zero || pid!=(uint)Process.Id) throw new InvalidOperationException("Window not owned by retained process");
        }
        string ClassName(IntPtr w) { var b=new StringBuilder(256); GetClassName(w,b,b.Capacity); return b.ToString(); }
        public string Text(IntPtr w) { return Text(w,3000); }
        string Text(IntPtr w,uint timeout) {
            Own(w); var b=new StringBuilder(32768); IntPtr result;
            if(SendMessageTimeout(w,13,(IntPtr)b.Capacity,b,2,timeout,out result)==IntPtr.Zero) throw new InvalidOperationException("WM_GETTEXT timeout");
            return b.ToString();
        }
        WindowInfo Info(IntPtr w) { return new WindowInfo {Handle=w,Class=ClassName(w),Id=GetDlgCtrlID(w),Text=Text(w)}; }
        public WindowInfo[] Windows() {
            Identity(); var found=new List<WindowInfo>();Exception error=null;
            EnumWindows((w,a)=>{uint p; GetWindowThreadProcessId(w,out p); if(p==(uint)Process.Id && IsWindowVisible(w)) {
                try {found.Add(Info(w));} catch(Exception e) {if(IsWindow(w)){error=e;return false;}}
            }return true;},IntPtr.Zero);
            if(error!=null)throw new InvalidOperationException("Owned window enumeration failed",error);
            return found.ToArray();
        }
        public WindowInfo[] Children(IntPtr parent) {
            Own(parent); var found=new List<WindowInfo>();Exception error=null;
            EnumChildWindows(parent,(w,a)=>{try {Own(w);found.Add(Info(w));}catch(Exception e){if(IsWindow(w)){error=e;return false;}}return true;},IntPtr.Zero);
            if(error!=null)throw new InvalidOperationException("Owned child enumeration failed",error);return found.ToArray();
        }
        public IntPtr Control(int id) { Own(Main); var w=GetDlgItem(Main,id);Own(w);return w; }
        public bool Enabled(int id) { return IsWindowEnabled(Control(id)); }
        public bool MenuEnabled(int id) {
            Own(Main);uint state=GetMenuState(GetMenu(Main),(uint)id,0);
            if(state==0xFFFFFFFF)throw new InvalidOperationException("Menu command missing: "+id);
            return (state&3)==0;
        }
        public bool MainEnabled() { Own(Main);return IsWindowEnabled(Main); }
        public bool Visible() { Own(Main);return IsWindowVisible(Main); }
        public bool Minimized() { Own(Main);return IsIconic(Main); }
        public bool ForegroundIsOwn() { Identity();uint pid;GetWindowThreadProcessId(GetForegroundWindow(),out pid);return pid==(uint)Process.Id; }
        public int Style(IntPtr w) { Own(w); return GetWindowLong(w,-16); }
        public int Count() { Own(Control(2005)); IntPtr r; if(SendMessageTimeout(Control(2005),0x1004,IntPtr.Zero,IntPtr.Zero,2,3000,out r)==IntPtr.Zero) throw new InvalidOperationException("List count timeout");return r.ToInt32(); }
        public uint Dpi() { Own(Main); return GetDpiForWindow(Main); }
        public bool Elevated() {
            Identity();IntPtr token;if(!OpenProcessToken(Process.Handle,8,out token))throw new InvalidOperationException("OpenProcessToken query failed");
            try {int elevation,returned;if(!GetTokenInformation(token,20,out elevation,4,out returned))throw new InvalidOperationException("TokenElevation query failed");return elevation!=0;}
            finally {CloseHandle(token);}
        }
        public string Manifest() {
            Identity();var library=LoadLibraryEx(executable,IntPtr.Zero,0x22); // DATAFILE | IMAGE_RESOURCE; never execute entry point.
            if(library==IntPtr.Zero)throw new InvalidOperationException("Load resource-only EXE failed");
            try {
                var resource=FindResource(library,(IntPtr)1,(IntPtr)24);uint size=SizeofResource(library,resource);
                if(resource==IntPtr.Zero || size==0 || size>1048576)throw new InvalidOperationException("Invalid manifest resource");
                var data=LockResource(LoadResource(library,resource));if(data==IntPtr.Zero)throw new InvalidOperationException("Load manifest failed");
                var bytes=new byte[size];Marshal.Copy(data,bytes,0,(int)size);return Encoding.UTF8.GetString(bytes);
            }finally {FreeLibrary(library);}
        }
        public void PrintPreview(IntPtr dc) {
            var preview=Control(2005);Own(preview);
            // Only the fixture ListView client, never the desktop, dialogs or log/user paths.
            if(!PrintWindow(preview,dc,1)) throw new InvalidOperationException("PrintWindow(preview) failed");
        }
        static bool ProviderUnavailable(int hr) {
            // E_FAIL/access denied/RPC/provider crashes are errors, not evidence of
            // absent capability. Only documented unsupported-interface/operation codes skip.
            return hr==unchecked((int)0x80004002) || hr==unchecked((int)0x80004001) || hr==unchecked((int)0x80070032);
        }
        static bool MissingChild(Exception e) {
            return e is ArgumentException || (e is COMException && e.HResult==unchecked((int)0x80070057));
        }
        bool AccessibleFields(IntPtr window,List<string> names,List<string> values,out string unavailable) {
            var iid=new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");Accessible acc;
            int hr=AccessibleObjectFromWindow(window,0xFFFFFFFC,ref iid,out acc);
            unavailable=null;
            if(hr<0) {
                if(acc!=null)Marshal.ReleaseComObject(acc);
                if(ProviderUnavailable(hr)) {unavailable="MSAA provider unavailable: 0x"+hr.ToString("X8");return false;}
                Marshal.ThrowExceptionForHR(hr);
            }
            if(acc==null) {unavailable="MSAA returned no provider";return false;}
            try {
                int count;
                try {count=acc.ChildCount;}
                catch(COMException e) {if(!ProviderUnavailable(e.HResult))throw;unavailable="MSAA child enumeration unsupported: 0x"+e.HResult.ToString("X8");return false;}
                if(count<0)throw new InvalidOperationException("MSAA invalid child count");
                for(int i=1;i<=Math.Min(count,16);i++) {
                    try {names.Add(acc.Name(i));}
                    catch(Exception e) {if(!MissingChild(e))throw;continue;}
                    try {
                        string value;int valueHr=acc.Value(i,out value);
                        if(valueHr==0)values.Add(value); // Keep even null/empty successful values.
                        else if(valueHr!=1 && valueHr!=unchecked((int)0x80020003) && valueHr!=unchecked((int)0x80004001) && valueHr!=unchecked((int)0x80070057)) {
                            if(valueHr>=0)throw new InvalidOperationException("Unexpected MSAA accValue status: "+valueHr);
                            Marshal.ThrowExceptionForHR(valueHr);
                        }
                    }
                    catch(Exception e) {
                        // An absent optional accValue is a known per-field capability gap,
                        // not permission to hide errors/semantic failures in readable fields.
                        if(!MissingChild(e) && !(e is COMException &&
                            (e.HResult==unchecked((int)0x80020003) || e.HResult==unchecked((int)0x80004001))))throw;
                    }
                }
                return true;
            } finally {Marshal.ReleaseComObject(acc);}
        }
        public AccessibilityProbe ProbePreviewAccessibility() {
            var list=Control(2005);IntPtr header;
            if(SendMessageTimeout(list,0x101F,IntPtr.Zero,IntPtr.Zero,2,3000,out header)==IntPtr.Zero) throw new InvalidOperationException("Get list header failed");
            Own(header);var probe=new AccessibilityProbe();
            var names=new List<string>();var values=new List<string>();string reason;
            probe.HeaderAvailable=AccessibleFields(header,names,values,out reason);
            probe.HeaderUnavailableReason=reason;probe.HeaderNames=names.ToArray();
            names.Clear();values.Clear();
            bool rowsAvailable=AccessibleFields(list,names,values,out reason);
            probe.ReadableRowNames=names.ToArray();probe.UnicodeValues=values.ToArray();
            probe.UnicodeAvailable=rowsAvailable && values.Count>0;
            probe.UnicodeUnavailableReason=rowsAvailable?"This provider exposes row names, but no accValue property (S_FALSE/unsupported); Unicode subcolumns remain unverified":reason;
            return probe;
        }
        public void Command(int id) {
            if(id!=1001 && id!=1002) throw new InvalidOperationException("Only open/save commands permitted");
            Own(Main); if(!Enabled(id)) throw new InvalidOperationException("Command disabled");
            if(!PostMessage(Main,0x111,(IntPtr)id,IntPtr.Zero)) throw new InvalidOperationException("WM_COMMAND failed");
        }
        public void Close() { Own(Main); if(!PostMessage(Main,0x10,IntPtr.Zero,IntPtr.Zero)) throw new InvalidOperationException("Close failed"); }
        void Dialog(IntPtr dialog) {
            Own(dialog); string title=Text(dialog);
            if(ClassName(dialog)!="#32770" || !(title.StartsWith("打开码表：") || title.StartsWith("另存为新 lex：") || title=="LexHelper — 码表尚未另存" || title=="LexHelper — 操作未成功")) throw new InvalidOperationException("Unexpected dialog; no action allowed: "+title);
        }
        public void DialogButton(IntPtr dialog,int id) {
            Dialog(dialog); var title=Text(dialog);
            if(title=="LexHelper — 码表尚未另存") {
                if(id!=2 && id!=6 && id!=7) throw new InvalidOperationException("Unexpected unsaved choice");
                // TaskDialog DirectUI button HWNDs have ID 0; the documented message uses
                // the application's known TaskDialog button IDs (not arbitrary HWND clicks).
                if(!PostMessage(dialog,0x400+102,(IntPtr)id,IntPtr.Zero)) throw new InvalidOperationException("TDM_CLICK_BUTTON failed");
                return;
            }
            else if(title=="LexHelper — 操作未成功") { if(id!=1) throw new InvalidOperationException("Only acknowledge error"); }
            else if(id!=1 && id!=2) throw new InvalidOperationException("Only accept/cancel file dialog");
            IntPtr button=IntPtr.Zero;
            foreach(var w in Children(dialog)) if(w.Id==id && w.Class=="Button" && IsWindowVisible(w.Handle)) { if(button!=IntPtr.Zero) throw new InvalidOperationException("Ambiguous button ID"); button=w.Handle; }
            // This Windows build exposes the sole MB_OK acknowledgement as IDCANCEL=2.
            // Permit that exact known ID only for this application's error title and OK label.
            if(button==IntPtr.Zero && title=="LexHelper — 操作未成功" && id==1)
                foreach(var w in Children(dialog)) if(w.Id==2 && w.Class=="Button" && (w.Text=="确定" || w.Text=="OK") && IsWindowVisible(w.Handle)) button=w.Handle;
            if(button==IntPtr.Zero) {
                var ids=new StringBuilder();foreach(var w in Children(dialog))ids.Append(w.Id+":"+w.Class+(w.Class=="Button"?":"+w.Text:"")+";");
                throw new InvalidOperationException("Known dialog button "+id+" missing: "+ids);
            }
            Own(button);
            // BM_CLICK alone need not transfer focus. Native file dialogs commit the
            // filename edit on focus loss; without it a previous selection can win.
            // WM_NEXTDLGCTL targets only this authenticated dialog, not global input.
            if((title.StartsWith("打开码表：") || title.StartsWith("另存为新 lex：")) && id==1) {
                IntPtr focusResult;
                if(SendMessageTimeout(dialog,0x28,button,(IntPtr)1,2,3000,out focusResult)==IntPtr.Zero)throw new InvalidOperationException("File dialog accept focus transfer failed");
            }
            if(!PostMessage(button,0xF5,IntPtr.Zero,IntPtr.Zero)) throw new InvalidOperationException("BM_CLICK failed");
        }
        public void FileName(IntPtr dialog,string path) {
            Dialog(dialog); string title=Text(dialog);
            if(!(title.StartsWith("打开码表：") || title.StartsWith("另存为新 lex："))) throw new InvalidOperationException("Not a file dialog");
            path=Path.GetFullPath(path);
            if(!path.StartsWith(root,StringComparison.OrdinalIgnoreCase) || !(path.EndsWith(".txt",StringComparison.OrdinalIgnoreCase)||path.EndsWith(".lex",StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("File path outside fixture allowlist");
            IntPtr edit=IntPtr.Zero;
            // IFileDialog filename combo cmb13=1148; do not target the address/search edit.
            bool saving=title.StartsWith("另存为新 lex：");
            foreach(var w in Children(dialog)) if(w.Id==(saving?1001:1148) && w.Class=="Edit" && IsWindowVisible(w.Handle)) {
                var parent=GetParent(w.Handle); Own(parent);
                if(ClassName(parent)!="ComboBox" || GetDlgCtrlID(parent)!=(saving?0:1148)) throw new InvalidOperationException("Unexpected filename edit parent");
                if(edit!=IntPtr.Zero) throw new InvalidOperationException("Ambiguous filename field");edit=w.Handle;
            }
            if(edit==IntPtr.Zero) {
                var ids=new StringBuilder(); foreach(var w in Children(dialog)) if(w.Class=="Edit" || w.Class=="ComboBox" || w.Class=="Button") ids.Append(w.Id+":"+w.Class+";");
                throw new InvalidOperationException("Known filename Edit ID missing; observed IDs/classes only: "+ids);
            }
            Own(edit); IntPtr result;
            if(SendMessageTimeout(dialog,0x28,edit,(IntPtr)1,2,3000,out result)==IntPtr.Zero)throw new InvalidOperationException("File dialog filename focus transfer failed");
            if(SendMessageTimeout(edit,12,IntPtr.Zero,path,2,3000,out result)==IntPtr.Zero || result==IntPtr.Zero) throw new InvalidOperationException("Set file name failed");
            if(!String.Equals(Text(edit),path,StringComparison.Ordinal))throw new InvalidOperationException("File dialog filename read-back mismatch");
            // WM_SETTEXT does not simulate the combo's user-edit notification. Tell
            // the filename host about this exact owned combo edit, not a stale selected item.
            IntPtr combo=GetParent(edit),host=GetParent(combo);Own(combo);Own(host);
            int notification=(5<<16)|(GetDlgCtrlID(combo)&0xFFFF); // CBN_EDITCHANGE
            if(SendMessageTimeout(host,0x111,(IntPtr)notification,combo,2,3000,out result)==IntPtr.Zero)throw new InvalidOperationException("File dialog filename change notification failed");
        }
        public Rect Client() { Own(Main); Rect r;if(!GetClientRect(Main,out r)) throw new InvalidOperationException("GetClientRect");return r; }
        public Rect Bounds(IntPtr w) { Own(w);Rect r;if(!GetWindowRect(w,out r)) throw new InvalidOperationException("GetWindowRect");return r; }
        public void MinimumSize() {
            Own(Main); uint dpi=Dpi(); var r=new Rect {Right=(int)(840*dpi/96),Bottom=(int)(570*dpi/96)};
            if(!AdjustWindowRectExForDpi(ref r,0x00CF0000,true,0,dpi)) throw new InvalidOperationException("AdjustWindowRectExForDpi");
            if(!SetWindowPos(Main,IntPtr.Zero,0,0,r.Right-r.Left,r.Bottom-r.Top,0x16)) throw new InvalidOperationException("SetWindowPos");
        }
        public int FocusId() { Own(Main);uint p;uint t=GetWindowThreadProcessId(Main,out p);var g=new GuiInfo {Size=Marshal.SizeOf<GuiInfo>()};if(!GetGUIThreadInfo(t,ref g)) throw new InvalidOperationException("GetGUIThreadInfo");if(g.Focus==IntPtr.Zero)return 0;Own(g.Focus);return GetDlgCtrlID(g.Focus); }
        public void Tab() {
            Own(Main); uint p;uint t=GetWindowThreadProcessId(Main,out p);var g=new GuiInfo {Size=Marshal.SizeOf<GuiInfo>()};if(!GetGUIThreadInfo(t,ref g)) throw new InvalidOperationException("GetGUIThreadInfo");
            IntPtr target=g.Focus==IntPtr.Zero?Main:g.Focus;Own(target);
            PostMessage(target,0x100,(IntPtr)9,(IntPtr)1);PostMessage(target,0x101,(IntPtr)9,new IntPtr(unchecked((int)0xC0000001)));
        }
        public CleanupResult CloseNormally(int milliseconds,bool allowKnownDialogs) {
            if(milliseconds<1 || milliseconds>60000)throw new ArgumentOutOfRangeException(nameof(milliseconds));
            var result=new CleanupResult {Identity=OriginalIdentity,State="Unknown",Reason="Cleanup not completed"};
            var timer=Stopwatch.StartNew();bool closePosted=false;
            try {
                while(!Process.HasExited && timer.ElapsedMilliseconds<milliseconds) {
                    Identity();var windows=new List<IntPtr>();Exception enumerationError=null;
                    EnumWindows((w,a)=>{
                        try {uint pid;GetWindowThreadProcessId(w,out pid);if(pid==(uint)Process.Id && IsWindowVisible(w))windows.Add(w);return true;}
                        catch(Exception e) {enumerationError=e;return false;}
                    },IntPtr.Zero);
                    if(enumerationError!=null)throw new InvalidOperationException("Cleanup window enumeration failed",enumerationError);
                    foreach(var window in windows) {
                        long remaining=milliseconds-timer.ElapsedMilliseconds;if(remaining<=0)break;
                        Own(window);string cls=ClassName(window);
                        if(cls=="LexHelper.MainWindow") {
                            Main=window;
                            if(!closePosted && IsWindowEnabled(window)) {Close();closePosted=true;}
                        } else if(cls=="#32770") {
                            string title=Text(window,(uint)Math.Min(remaining,200));
                            if(title=="LexHelper — 无法启动" || title=="LexHelper") {
                                Own(window);if(!PostMessage(window,0x10,IntPtr.Zero,IntPtr.Zero))throw new InvalidOperationException("Startup dialog normal close failed");
                            } else if(allowKnownDialogs) {
                                if(title=="LexHelper — 码表尚未另存") {
                                    Own(window);if(!PostMessage(window,0x400+102,(IntPtr)7,IntPtr.Zero))throw new InvalidOperationException("Known unsaved dialog normal discard failed");
                                }
                                // WM_CLOSE cancels file dialogs or acknowledges known MB_OK,
                                // avoiding unbounded child enumeration during cleanup.
                                else if(title=="LexHelper — 操作未成功" || title.StartsWith("打开码表：") || title.StartsWith("另存为新 lex：")) {
                                    Own(window);if(!PostMessage(window,0x10,IntPtr.Zero,IntPtr.Zero))throw new InvalidOperationException("Known dialog normal close failed");
                                    closePosted=false;
                                }
                            }
                        }
                    }
                    int wait=(int)Math.Min(100,Math.Max(0,milliseconds-timer.ElapsedMilliseconds));
                    if(Process.WaitForExit(wait))break;
                }
                result.State=Process.HasExited?"Exited":"LeftRunning";
                result.Reason=Process.HasExited?"Original retained process exited; no force termination":"Normal-close budget expired or no safely recognized enabled window; no force termination";
                if(Process.HasExited)result.ExitCode=Process.ExitCode;
            } catch(Exception e) {
                result.Reason="Normal close refused/failed: "+e.Message+"; no force termination";
                try {result.State=Process.HasExited?"Exited":"LeftRunning";if(Process.HasExited)result.ExitCode=Process.ExitCode;}
                catch(Exception statusError) {result.State="Unknown";result.Reason+="; process lifetime query failed: "+statusError.Message;}
            }
            return result;
        }
        public void Dispose() { if(Process!=null) Process.Dispose(); }
    }
}
