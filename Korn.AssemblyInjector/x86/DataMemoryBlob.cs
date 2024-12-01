using System.Text;

class DataMemoryBlob(MemoryBlob MemoryBlob) : MemoryBlob(MemoryBlob.ProcessHandle, MemoryBlob.PageBase, MemoryBlob.Size, MemoryBlob.Position)
{
    public nint AllocateWString(string text)
    {
        var address = MemoryBlob.Cursor;
        MemoryBlob.Write(Encoding.Unicode.GetBytes(text));
        MemoryBlob.Write([0, 0]);
        return address;
    }
}