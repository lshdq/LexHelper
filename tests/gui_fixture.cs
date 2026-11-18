// Test-only ordinary native window. No LexHelper code, data, dialogs or system actions.
// Build with the locally installed .NET Framework C# compiler; not a product dependency.
using System;
using System.Runtime.InteropServices;

static class GuiSupportFixture {
    delegate IntPtr WindowProc(IntPtr window,uint message,IntPtr wparam,IntPtr lparam);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct WindowClass {
        public uint Style;public WindowProc Proc;public int ClassExtra,WindowExtra;
        public IntPtr Instance,Icon,Cursor,Background;public string Menu,Name;
    }
    [StructLayout(LayoutKind.Sequential)] struct Point {public int X,Y;}
    [StructLayout(LayoutKind.Sequential)] struct Message {
        public IntPtr Window;public uint Id;public IntPtr Wparam,Lparam;public uint Time;public Point Point;public uint Private;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string module);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ushort RegisterClass(ref WindowClass cls);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool UnregisterClass(string cls,IntPtr instance);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateWindowEx(uint ex,string cls,string title,uint style,int x,int y,int width,int height,IntPtr parent,IntPtr menu,IntPtr instance,IntPtr parameter);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr window,int show);
    [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr window);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr window);
    [DllImport("user32.dll")] static extern void PostQuitMessage(int code);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetMessage(out Message message,IntPtr window,uint min,uint max);
    [DllImport("user32.dll")] static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr DispatchMessage(ref Message message);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr DefWindowProc(IntPtr window,uint message,IntPtr wparam,IntPtr lparam);
    [DllImport("user32.dll")] static extern UIntPtr SetTimer(IntPtr window,UIntPtr id,uint ms,IntPtr callback);
    static readonly WindowProc Callback=Procedure;
    static IntPtr Procedure(IntPtr window,uint message,IntPtr wparam,IntPtr lparam) {
        // No managed exception may escape a native callback.
        try {
            if(message==0x10 || message==0x113) {DestroyWindow(window);return IntPtr.Zero;}
            if(message==2) {PostQuitMessage(0);return IntPtr.Zero;}
        } catch {PostQuitMessage(3);return IntPtr.Zero;}
        return DefWindowProc(window,message,wparam,lparam);
    }
    [STAThread] static int Main() {
        bool unknown=System.Reflection.Assembly.GetExecutingAssembly().Location.IndexOf("unknown",StringComparison.OrdinalIgnoreCase)>=0;
        string name=unknown?"LexHelper.GuiSupport.Unknown":"LexHelper.MainWindow";
        var instance=GetModuleHandle(null);
        var cls=new WindowClass {Proc=Callback,Instance=instance,Name=name};
        if(RegisterClass(ref cls)==0)return 2;
        IntPtr window=IntPtr.Zero;
        try {
            window=CreateWindowEx(0,name,"GUI support self-test fixture (not LexHelper)",0x00CF0000,0,0,320,200,IntPtr.Zero,IntPtr.Zero,instance,IntPtr.Zero);
            if(window==IntPtr.Zero)return 2;
            // Safety expiry even if the harness breaks; WM_TIMER uses this fixture's own loop.
            if(SetTimer(window,(UIntPtr)1,12000,IntPtr.Zero)==UIntPtr.Zero)return 2;
            ShowWindow(window,7); // minimized, no activation; never TOPMOST/foreground
            Message message;int result;
            while((result=GetMessage(out message,IntPtr.Zero,0,0))>0) {TranslateMessage(ref message);DispatchMessage(ref message);}
            return result<0?2:message.Wparam.ToInt32();
        } finally {
            if(window!=IntPtr.Zero && IsWindow(window))DestroyWindow(window);
            UnregisterClass(name,instance);
            GC.KeepAlive(Callback);
        }
    }
}
