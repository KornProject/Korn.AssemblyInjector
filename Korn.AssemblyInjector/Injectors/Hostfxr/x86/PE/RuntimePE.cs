using Korn.Utils;

unsafe class RuntimePE
{
    public RuntimePE(nint processHandle, nint address) : this(*(ExternalMemory*)&processHandle, address) { }

    public RuntimePE(ExternalMemory memory, nint address)
    {
        ProcessHandle = processHandle;
        pointer = peBase;

        e_lfanew = Interop.ReadProcessMemory<uint>(
            ProcessHandle, 
            pointer
            + 0x3C
        );

        optionalHeader = Interop.ReadProcessMemory<ImageOptionalHeader64>(
            ProcessHandle, 
            pointer
            + (nint)e_lfanew
            + 4
            + 20
        );

        fileHeader = Interop.ReadProcessMemory<ImageFileHeader>(
            ProcessHandle, 
            pointer 
            + (nint)e_lfanew
            + 4
         );

        exportDirectory = Interop.ReadProcessMemory<ImageExportDirectory>(
            ProcessHandle, 
            pointer 
            + (nint)optionalHeader.ExportTable.VirtualAddress
        );

        _ = 3;
    }

    ExternalMemory memory;
    nint pointer;

    uint e_lfanew;
    ImageOptionalHeader64 optionalHeader;
    ImageFileHeader fileHeader;
    ImageExportDirectory exportDirectory;

    public nint GetExportFunctionAddress(ReadOnlySpan<byte> name) => pointer + (nint)GetEATFunction(name);

    uint GetEATFunction(ReadOnlySpan<byte> targetName)
    {
        var index = GetEATFunctionIndex(targetName);
        if (index == -1)
            return 0;
        else
            return Interop.ReadProcessMemory<uint>(
                ProcessHandle, 
                pointer + 
                + (nint)exportDirectory.AddressOfFunctions
                + (nint)index * sizeof(uint)
            );
    }

    long GetEATFunctionIndex(ReadOnlySpan<byte> targetName)
    {
        for (uint i = 0; i < exportDirectory.NumberOfNames; i++)
        {
            var nameRva = Interop.ReadProcessMemory<uint>(
                ProcessHandle,
                pointer + 
                + (nint)exportDirectory.AddressOfNames
                + (nint)i * sizeof(uint)
            );
            var name = pointer + (nint)nameRva;
            var isFound = true;
            for (var o = 0; o < targetName.Length; o++)
            {
                if (Interop.ReadProcessMemory<byte>(ProcessHandle, name + o) != targetName[o])
                {
                    isFound = false;
                    break;
                }
            }

            if (isFound)
                return i;
        }
        return -1;
    }
}