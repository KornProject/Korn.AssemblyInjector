using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct ImageDataDirectory
{
    public uint VirtualAddress;
    public uint Size;
}