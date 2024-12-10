using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
unsafe struct ImageSectionHeader
{
    public fixed byte Name[8];
    public uint VirtualSize;
    public uint VirtualAddress;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;
}