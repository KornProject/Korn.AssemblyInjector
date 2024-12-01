unsafe class Assembler
{
    public Assembler(MemoryBlob memoryBlob)
    {
        MemoryBlob = memoryBlob;
    }

    public readonly MemoryBlob MemoryBlob;

    public void Ret() => MemoryBlob.Write(OpCodes.Ret);

    public void Call() => MemoryBlob.Write(OpCodes.CallRax);

    public void Call(nint address)
    {
        var position = MemoryBlob.Position;

        var relativeAddress = address - position;
        
        if (CanPerformRelative32JumpOrCall(position, address))
        {
            var offset = (int)(address - position);
            MemoryBlob.Write([OpCodes.RelativeCall, ..BitConverter.GetBytes(offset)]);
        }
        else
        {
            MovToRax(address);
            Call();
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
        else if (CanPerformRelative32JumpOrCall(position, address))
        {
            var offset = (int)(address - position);
            MemoryBlob.Write([OpCodes.Relative32Jump, .. BitConverter.GetBytes(offset)]);
        }
        else
        {
            MovToRax(address);
            MemoryBlob.Write(OpCodes.JumpRax);
        }
    }

    public void MovToRax(long value)
    {
        if (IsInt32(value))
            MemoryBlob.Write([.. OpCodes.Mov32Rax, .. BitConverter.GetBytes((int)value)]);
        else MemoryBlob.Write([.. OpCodes.Mov64Rax, .. BitConverter.GetBytes(value)]);
    }

    public void MovToRbx(long value)
    {
        if (IsInt32(value))
            MemoryBlob.Write([.. OpCodes.Mov32Rbx, .. BitConverter.GetBytes((int)value)]);
        else MemoryBlob.Write([.. OpCodes.Mov64Rbx, .. BitConverter.GetBytes(value)]);
    }

    public void MovToRelativeRsp(int offset, long value)
    {
        if (IsInt32(value))
        {
            if (IsInt8(offset))
                MemoryBlob.Write([.. OpCodes.Mov32Rel8Rsp, *(byte*)&offset, ..BitConverter.GetBytes((int)value)]);
            else MemoryBlob.Write([.. OpCodes.Mov32Rel32Rsp, .. BitConverter.GetBytes(offset), ..BitConverter.GetBytes((int)value)]);
        }
        else
        {
            MovToRbx(value);
            MovRbxToRelativeRsp(offset);
        }
    }

    public void MovRbxToRelativeRsp(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRbxRel8Rsp, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRbxRel32Rsp, .. BitConverter.GetBytes(offset)]);
    }

    public void PushRelativeRsp(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.PushRel8Rsp, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.PushRel32Rsp, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRbx(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRbx, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRbx, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRdi(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRdi, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRdi, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRsi(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRsi, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRsi, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRdx(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRdx, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRdx, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRcx(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRcx, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRcx, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToR8(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspR8, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspR8, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToR9(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspR9, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspR9, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRelativeRspToRax(int offset)
    {
        if (IsInt8(offset))
            MemoryBlob.Write([.. OpCodes.MovRel8RspRax, *(byte*)&offset]);
        else MemoryBlob.Write([.. OpCodes.MovRel32RspRax, .. BitConverter.GetBytes(offset)]);
    }

    public void MovRspToRbx() => MemoryBlob.Write(OpCodes.MovRspRbx);

    public void AddRsp(int value)
    {
        if (IsInt8(value))
            MemoryBlob.Write([.. OpCodes.Add8Rsp, *(byte*)&value]);
        else MemoryBlob.Write([.. OpCodes.Add32Rsp, .. BitConverter.GetBytes(value)]);
    }

    public void SubRsp(int value)
    {
        if (IsInt8(value))
            MemoryBlob.Write([.. OpCodes.Sub8Rsp, *(byte*)&value]);
        else MemoryBlob.Write([.. OpCodes.Sub32Rsp, .. BitConverter.GetBytes(value)]);
    }

    public void AddRbx(int value)
    {
        if (IsInt8(value))
            MemoryBlob.Write([.. OpCodes.Add8Rbx, *(byte*)&value]);
        else MemoryBlob.Write([.. OpCodes.Add32Rbx, .. BitConverter.GetBytes(value)]);
    }

    public void PushRbx() => MemoryBlob.Write(OpCodes.PushRbx);
    public void PushRdi() => MemoryBlob.Write(OpCodes.PushRdi);
    public void PushRsi() => MemoryBlob.Write(OpCodes.PushRsi);
    public void PushRdx() => MemoryBlob.Write(OpCodes.PushRdx);
    public void PushRcx() => MemoryBlob.Write(OpCodes.PushRcx);
    public void PushR8() => MemoryBlob.Write(OpCodes.PushR8);
    public void PushR9() => MemoryBlob.Write(OpCodes.PushR9);

    public void PopRbx() => MemoryBlob.Write(OpCodes.PopRbx);
    public void PopRdi() => MemoryBlob.Write(OpCodes.PopRdi);
    public void PopRsi() => MemoryBlob.Write(OpCodes.PopRsi);
    public void PopRdx() => MemoryBlob.Write(OpCodes.PopRdx);
    public void PopRcx() => MemoryBlob.Write(OpCodes.PopRcx);
    public void PopR8() => MemoryBlob.Write(OpCodes.PopR8);
    public void PopR9() => MemoryBlob.Write(OpCodes.PopR9);

    bool CanPerformShortJump(nint position, nint address)
    {
        var instructionSize = 1 + sizeof(sbyte);
        var relativeAddress = address - position + instructionSize;
        return IsInt8(relativeAddress);
    }

    bool CanPerformRelative32JumpOrCall(nint position, nint address)
    {
        var instructionSize = 1 + sizeof(int);
        var relativeAddress = address - position + instructionSize;
        return IsInt32(relativeAddress);
    }

    bool IsInt8(long value) => value is >= sbyte.MinValue and <= sbyte.MaxValue;
    bool IsInt16(long value) => value is >= short.MinValue and <= short.MaxValue;
    bool IsInt32(long value) => value is >= int.MinValue and <= int.MaxValue;
}