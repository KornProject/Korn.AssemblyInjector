class MemoryBlob
{
    public MemoryBlob(nint processHandle, nint pageBase, int size, nint position = 0)
    {
        ProcessHandle = processHandle;
        PageBase = pageBase;
        Size = size;
        Position = position;
    }

    public readonly nint ProcessHandle;
    public readonly nint PageBase;
    public readonly int Size;

    public nint Position;
    public nint Cursor => PageBase + Position;

    public nint Allocate(int size)
    {
        var position = Position;
        Position = position + size;
        return PageBase + position;
    }

    public nint Write(params byte[] bytes)
    {
        var position = Position;
        SilentWrite(position, bytes);

        Position += bytes.Length;

        return PageBase + position;
    }

    public void SilentWrite(nint position, byte[] bytes) 
        => Interop.WriteProcessMemory(ProcessHandle, Cursor, bytes, (uint)bytes.Length, out int written);

    public void FillBy(byte value) => SilentWrite(0, Enumerable.Repeat(value, Size).ToArray());

    public MemoryBlob ExtractBlob(int start, int size) => new MemoryBlob(ProcessHandle, PageBase + start, size);

    public static MemoryBlob Allocate(nint processHandle, int initPageSize = 4096)
    {
        const int MEM_COMMIT = 0x1000;
        const int PAGE_EXECUTE_READWRITE = 0x40;

        var pagebase = Interop.VirtualAllocEx(processHandle, 0, (uint)initPageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        return new MemoryBlob(processHandle, pagebase, initPageSize);
    }
}