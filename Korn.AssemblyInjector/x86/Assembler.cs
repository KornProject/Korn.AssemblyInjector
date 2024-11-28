unsafe class Assembler(MemoryBlob MemoryBlob)
{
    public void Call(nint address)
    {
        var position = MemoryBlob.Position;

        var relativeAddress = address - position;
        
        if (CanPerformRelativeCall(position, address))
        {
            var offset = (int)(address - position);
            MemoryBlob.Write([OpCodes.RelativeCall, ..BitConverter.GetBytes(offset)]);
        }
        else
        {
            Mov64Rax(address);
            MemoryBlob.Write(OpCodes.CallRax);
        }
    }

    public void Jump(nint address)
    {
        var position = MemoryBlob.Position;

        var relativeAddress = address - position;

        if (CanPerformShortJump(position, address))
        {
            var offset = (sbyte)(address - position);
            MemoryBlob.Write(OpCodes.ShortJump, *(byte*)&offset);
        }
        else if (CanPerformRelative32Jump(position, address))
        {
            var offset = (int)(address - position);
            MemoryBlob.Write([OpCodes.Relative32Jump, .. BitConverter.GetBytes(offset)]);
        }
        else
        {
            Mov64Rax(address);
            MemoryBlob.Write(OpCodes.JumpRax);
        }
    }

    public void Mov64Rax(nint value)
    {
        MemoryBlob.Write([..OpCodes.Mov64Rax, ..BitConverter.GetBytes(value)]);
    }

    bool CanPerformShortJump(nint position, nint address)
    {
        var instructionSize = 1 + sizeof(sbyte);
        var relativeAddress = address - position + instructionSize;
        return relativeAddress is >= sbyte.MinValue and <= sbyte.MaxValue;
    }

    bool CanPerformRelative32Jump(nint position, nint address)
    {
        var instructionSize = 1 + sizeof(int);
        var relativeAddress = address - position + instructionSize;
        return relativeAddress is >= int.MinValue and <= int.MaxValue;
    }

    bool CanPerformRelativeCall(nint position, nint address)
    {
        var instructionSize = 1 + sizeof(int);
        var relativeAddress = address - position + instructionSize;
        return relativeAddress is >= int.MinValue and <= int.MaxValue;
    }
}

static class OpCodes
{
    public static readonly byte ShortJump = 0xEB;
    public static readonly byte Relative32Jump = 0xE9;
    public static readonly byte RelativeCall = 0xE8;
    public static readonly byte[] Mov32Rax = [0x48, 0xC7, 0xC0];
    public static readonly byte[] Mov64Rax = [0x48, 0xB8];
    public static readonly byte[] JumpRax = [0xFF, 0xE0];
    public static readonly byte[] CallRax = [0xFF, 0xD0];
}