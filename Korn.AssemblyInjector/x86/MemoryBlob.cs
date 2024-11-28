record struct MemoryBlob(nint PageBase)
{
    public readonly nint PageBase;

    public static MemoryBlob Allocate(nint processHandle, int initPageSize = 4096)
    {
        const int MEM_COMMIT = 0x1000;
        const int PAGE_EXECUTE_READWRITE = 0x40;

        var pagebase = Interop.VirtualAllocEx(processHandle, unchecked((nint)0x7FFFFFFFFFFFFFFFUL), (uint)initPageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        return new MemoryBlob(pagebase);
    }
}