using System.Runtime.InteropServices;
using System.Text;

static unsafe class Interop
{
    const string kernel = "kernel32";
    const string psapi = "psapi";

    [DllImport(kernel)] public static extern
        nint OpenProcess(int desiredAccess, bool inheritHandle, int process);

    [DllImport(kernel)] public static extern
        bool CloseHandle(nint handle);

    [DllImport(kernel)] public static extern 
        nint VirtualAllocEx(nint process, nint address, uint size, uint allocationType, uint protect);

    [DllImport(kernel)] public static extern 
        bool VirtualFreeEx(nint process, nint address, int size, uint dwFreeType);

    [DllImport(kernel)] public static extern 
        bool WriteProcessMemory(nint process, nint address, byte[] buffer, uint size, out int written);

    [DllImport(kernel)] public static extern 
        bool ReadProcessMemory(nint process, nint address, byte[] buffer, uint size, out int written);

    [DllImport(kernel)] public static extern
        nint GetProcAddress(nint module, [MarshalAs(UnmanagedType.LPStr)] string name);

    [DllImport(kernel)] public static extern
        nint GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string name);

    [DllImport(kernel)] public static extern 
        nint CreateRemoteThread(nint process, nint threadAttribute, nint stackSize, nint startAddress, nint parameter, uint creationFlags, nint* threadId);

    [DllImport(kernel)] public static extern 
        uint WaitForSingleObject(nint handle, uint milliseconds);

    [DllImport(psapi)] public static extern
        bool EnumProcessModules(nint process, nint* module, int size, int* needed);

    [DllImport(psapi)] public static extern
        uint GetModuleFileNameEx(nint hProcess, nint module, StringBuilder baseName, int size);


    public static void WriteProcessMemory(nint process, nint address, byte[] buffer)
        => WriteProcessMemory(process, address, buffer, (uint)buffer.Length, out int _);

    public static byte[] ReadProcessMemory(nint process, nint address, int length)
    {
        var buffer = new byte[length];
        ReadProcessMemory(process, address, buffer, (uint)buffer.Length, out int _);

        return buffer;
    }

    public static T ReadProcessMemory<T>(nint process, nint address) where T : unmanaged
    {
        T value;

        var buffer = ReadProcessMemory(process, address, sizeof(T));
        fixed (byte* bufferPointer = buffer)
            *&value = *(T*)bufferPointer;
    
        return value;
    }
}