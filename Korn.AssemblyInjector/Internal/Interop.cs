using System.Runtime.InteropServices;

static class Interop
{
    const string kernel = "kernel32";

    [DllImport(kernel)] public static extern
        nint OpenProcess(int desiredAccess, bool inheritHandle, int process);

    [DllImport(kernel)] public static extern
        bool CloseHandle(nint handle);

    [DllImport(kernel)] public static extern 
        nint VirtualAllocEx(nint process, nint address, uint size, uint allocationType, uint protect);

    [DllImport(kernel)] public static extern 
        bool WriteProcessMemory(nint process, nint address, byte[] buffer, uint size, out int written);

}