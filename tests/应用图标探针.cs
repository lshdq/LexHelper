// TC-001/002/005: read-only PE resources and owned-window icon probes.
// No remote memory, system settings, elevation, install command or forced termination.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace LexHelperIconTest {
    public sealed class IconSnapshot {
        public int Width, Height;
        public string Pixels;
    }
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] struct IconInfo {
            public int IsIcon; public uint X, Y; public IntPtr Mask, Color;
        }
        [StructLayout(LayoutKind.Sequential)] struct Bitmap {
            public int Type, Width, Height, WidthBytes;
            public ushort Planes, BitsPixel; public IntPtr Bits;
        }
        [StructLayout(LayoutKind.Sequential)] struct BitmapInfo {
            public uint Size; public int Width, Height; public ushort Planes, BitCount;
            public uint Compression, ImageSize; public int XPels, YPels;
            public uint Used, Important;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
        [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
        [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
        [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr module, IntPtr resource);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadImageW(IntPtr module, IntPtr name, uint type, int x, int y, uint flags);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadIconW(IntPtr module, IntPtr name);
        [DllImport("user32.dll", SetLastError=true)] static extern IntPtr CopyImage(IntPtr image, uint type, int x, int y, uint flags);
        [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr icon);
        [DllImport("user32.dll")] static extern bool GetIconInfo(IntPtr icon, out IconInfo info);
        [DllImport("gdi32.dll")] static extern int GetObjectW(IntPtr bitmap, int size, out Bitmap value);
        [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr value);
        [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr dc);
        [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr dc);
        [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr dc, IntPtr bitmap, uint start, uint lines, byte[] pixels, ref BitmapInfo info, uint usage);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr SendMessageTimeoutW(IntPtr window, uint message, IntPtr wparam, IntPtr lparam, uint flags, uint timeout, out IntPtr result);
        [DllImport("user32.dll")] static extern IntPtr GetClassLongPtrW(IntPtr window, int index);
        [DllImport("user32.dll")] public static extern int GetSystemMetricsForDpi(int index, uint dpi);
        [DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr process, uint flags);

        public static byte[] Resource(string exe, int type, int id) {
            // LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE: never execute EXE code.
            IntPtr module=LoadLibraryExW(exe,IntPtr.Zero,0x22);
            if(module==IntPtr.Zero)throw new Win32Exception();
            try {
                IntPtr resource=FindResourceW(module,(IntPtr)id,(IntPtr)type);
                if(resource==IntPtr.Zero)throw new InvalidOperationException("Missing resource "+type+"/"+id);
                uint size=SizeofResource(module,resource);
                IntPtr data=LockResource(LoadResource(module,resource));
                if(size==0 || size>16*1024*1024 || data==IntPtr.Zero)throw new InvalidOperationException("Invalid resource");
                byte[] bytes=new byte[size];Marshal.Copy(data,bytes,0,bytes.Length);return bytes;
            } finally {FreeLibrary(module);}
        }
        public static IconSnapshot Snapshot(IntPtr icon) {
            IconInfo info;
            if(icon==IntPtr.Zero || !GetIconInfo(icon,out info))throw new InvalidOperationException("Invalid icon handle");
            IntPtr dc=IntPtr.Zero;
            try {
                Bitmap bitmap;
                if(info.Color==IntPtr.Zero || GetObjectW(info.Color,Marshal.SizeOf<Bitmap>(),out bitmap)==0)throw new InvalidOperationException("No color bitmap");
                if(bitmap.Width<=0 || bitmap.Width>1024 || bitmap.Height<=0 || bitmap.Height>1024)throw new InvalidOperationException("Invalid icon dimensions");
                var header=new BitmapInfo {Size=(uint)Marshal.SizeOf<BitmapInfo>(),Width=bitmap.Width,Height=-bitmap.Height,Planes=1,BitCount=32};
                byte[] pixels=new byte[checked(bitmap.Width*bitmap.Height*4)];
                dc=CreateCompatibleDC(IntPtr.Zero);
                if(dc==IntPtr.Zero || GetDIBits(dc,info.Color,0,(uint)bitmap.Height,pixels,ref header,0)!=bitmap.Height)throw new InvalidOperationException("Read icon pixels failed");
                return new IconSnapshot {Width=bitmap.Width,Height=bitmap.Height,Pixels=Convert.ToHexString(SHA256.HashData(pixels))};
            } finally {
                if(dc!=IntPtr.Zero)DeleteDC(dc);
                if(info.Color!=IntPtr.Zero)DeleteObject(info.Color);
                if(info.Mask!=IntPtr.Zero)DeleteObject(info.Mask);
            }
        }
        public static IconSnapshot Loaded(string exe, int width, int height, bool systemDefault) {
            IntPtr module=systemDefault?IntPtr.Zero:LoadLibraryExW(exe,IntPtr.Zero,0x22);
            if(!systemDefault && module==IntPtr.Zero)throw new Win32Exception();
            IntPtr icon=IntPtr.Zero;
            try {
                // Predefined icons are shared; create an owned resized copy, never destroy
                // the LoadIconW return. EXE images use non-shared LoadImageW as production.
                icon=systemDefault?CopyImage(LoadIconW(IntPtr.Zero,(IntPtr)32512),1,width,height,0):LoadImageW(module,(IntPtr)101,1,width,height,0);
                if(icon==IntPtr.Zero)throw new Win32Exception();
                return Snapshot(icon);
            } finally {if(icon!=IntPtr.Zero)DestroyIcon(icon);if(module!=IntPtr.Zero)FreeLibrary(module);}
        }
        public static IconSnapshot WindowIcon(IntPtr window, bool small, bool classIcon) {
            IntPtr icon;
            if(classIcon)icon=GetClassLongPtrW(window,small?-34:-14);
            else if(SendMessageTimeoutW(window,0x7f,(IntPtr)(small?0:1),IntPtr.Zero,2,3000,out icon)==IntPtr.Zero)throw new InvalidOperationException("WM_GETICON timeout");
            // Borrowed window/class handles: Snapshot only; never DestroyIcon.
            return Snapshot(icon);
        }
        public static void ReloadOwnedWindow(IntPtr window, int expectedPid) {
            uint pid;GetWindowThreadProcessId(window,out pid);
            if(pid!=(uint)expectedPid)throw new InvalidOperationException("Window owner mismatch");
            IntPtr result;
            // WM_THEMECHANGED only on our retained process, not a global broadcast.
            if(SendMessageTimeoutW(window,0x31a,IntPtr.Zero,IntPtr.Zero,2,3000,out result)==IntPtr.Zero)throw new InvalidOperationException("Reload timeout");
        }
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    }
}
