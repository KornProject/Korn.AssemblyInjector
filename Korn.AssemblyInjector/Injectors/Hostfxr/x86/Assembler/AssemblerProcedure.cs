using Korn;

unsafe class AssemblerProcedure : AssemblerX64
{
    public AssemblerProcedure(AssemblerX64 assembler, int stackSize = 0, ProcedureFlags flags = ProcedureFlags.None) : base(assembler.MemoryBlob)
    {
        Assembler = assembler;
        Address = assembler.MemoryBlob.PageBase + assembler.MemoryBlob.Position;

        Flags = flags;
        if (Flags.HasFlag(ProcedureFlags.AllowStackValue64))
            PushRbx();
        if (Flags.HasFlag(ProcedureFlags.ReserveAllArgRegisters))
        {
            PushRdi();
            PushRsi();
            PushRdx();
            PushRcx();
            PushR8();
            PushR9();
        }

        Stack = new(stackSize);
        if (stackSize != 0)
            AllocateStack(stackSize);
    }

    public readonly nint Address;
    public readonly AssemblerX64 Assembler;
    public readonly ProcedureFlags Flags;

    public readonly ProcedureStack Stack;
    readonly List<int> stackAllocates = [];

    void AllocateStack(int size)
    {
        stackAllocates.Add(size);
        SubRsp(size);
    }

    void FreeStack()
    {
        var totalSize = stackAllocates.Sum();
        if (totalSize == 0)
            return;

        AddRsp(totalSize);
    }

    public ProcedureLocalVariable CreateVariable<T>() where T : unmanaged
        => Stack.CreateLocalVariable<T>();

    public ProcedureLocalVariable InitializeVariable<T>(T value) where T : unmanaged
    {
        var size = sizeof(T);
        var variable = Stack.CreateLocalVariable<T>();

        if (size > 8)
            throw new KornError([
                "Assembler->InitializeVariable<T>(string, T):", 
                "Attempt to write too large a value to the stack. The maximum size of the value is 64 bits."
            ]);
        else if (size == 8)
        {
            if (!Flags.HasFlag(ProcedureFlags.AllowStackValue64))
                throw new KornError([
                    "[Korn.AssemblyInjector] Assembler->InitializeVariable<T>(string, T):",
                    "Attempt to write a 64-bit value to the stack when 64-bit values are disallowed.",
                    "Add AssemblerFlags.AllowStackValue64 to the assembler flags to allow these values."
                ]);
        }

        var longValue = size switch
        {
            8 => *(long*)&value,
            4 => *(int*)&value,
            2 => *(short*)&value,
            1 => *(byte*)&value,
            _ => throw new KornError([
                    "[Korn.AssemblyInjector] Assembler->InitializeVariable<T>(string, T):", 
                    "An unexpected size of the value. The size should be 64, 32, 16 or 8 bits."
                 ])
        };

        MovToRelativeRsp(variable.Offset, longValue);

        return variable;
    }

    public ProcedureLocalVariable CreatePointerToVariable(ProcedureLocalVariable target)
    {
        var variable = CreateVariable<nint>();

        MovRspToRbx();
        AddRbx(target.Offset);
        MovRbxToRelativeRsp(variable.Offset);

        return variable;
    }

    public void FastCallNoReturnPointer(ProcedureLocalVariable pointer, params ProcedureLocalVariable[] args)
    {
        var argsCount = args.Length;
        var stackOffset = 0;

        if (argsCount >= 1)
            MovRelativeRspToRcx(args[0].Offset);
        if (argsCount >= 2)
            MovRelativeRspToRdx(args[1].Offset);
        if (argsCount >= 3)
            MovRelativeRspToR8(args[2].Offset);
        if (argsCount >= 4)
            MovRelativeRspToR9(args[3].Offset);
        if (argsCount >= 5)
            for (var i = 4; i < argsCount; i++)
            {
                PushRelativeRsp(args[i].Offset + stackOffset);
                stackOffset += 8;
            }

        MovRelativeRspToRax(pointer.Offset + stackOffset);
        Call();

        if (stackOffset != 0)
            AddRsp(stackOffset);
    }

    public void CallHostFxrStubNoReturnPointer(ProcedureLocalVariable pointer, params ProcedureLocalVariable[] args)
    {
        var argsCount = args.Length;

        if (argsCount >= 1)
            MovRelativeRspToRcx(args[0].Offset);
        if (argsCount >= 2)
            MovRelativeRspToRdx(args[1].Offset);
        if (argsCount >= 3)
            MovRelativeRspToR8(args[2].Offset);
        if (argsCount >= 4)
            MovRelativeRspToR9(args[3].Offset);
        if (argsCount >= 5)
            for (var i = 4; i < argsCount; i++)
            {
                MovRelativeRspToRbx(args[i].Offset);
                MovRbxToRelativeRsp(8 * i); // … magic values
            }

        MovRelativeRspToRax(pointer.Offset);
        Call();
    }

    public void WriteEpilogue()
    {
        FreeStack();

        if (Flags.HasFlag(ProcedureFlags.AllowStackValue64))
            PopRbx();

        if (Flags.HasFlag(ProcedureFlags.ReserveAllArgRegisters))
        {
            PopRdi();
            PopRsi();
            PopRdx();
            PopRcx();
            PopR8();
            PopR9();
        }

        Ret();
    }
}