unsafe class RuntimePE
{
    public RuntimePE(nint processHandle, nint peBase)
    {
        ProcessHandle = processHandle;
        PEBase = peBase;

        e_lfanew = Interop.ReadProcessMemory<uint>(
            ProcessHandle, 
            PEBase
            + 0x3C
        );

        optionalHeader = Interop.ReadProcessMemory<ImageOptionalHeader64>(
            ProcessHandle, 
            PEBase
            + (nint)e_lfanew
            + 4
            + 20
        );

        fileHeader = Interop.ReadProcessMemory<ImageFileHeader>(
            ProcessHandle, 
            PEBase 
            + (nint)e_lfanew
            + 4
         );

        exportDirectory = Interop.ReadProcessMemory<ImageExportDirectory>(
            ProcessHandle, 
            PEBase 
            + (nint)optionalHeader.ExportTable.VirtualAddress
        );

        _ = 3;
    }
    
    readonly nint ProcessHandle;
    readonly nint PEBase;

    readonly uint e_lfanew;
    readonly ImageOptionalHeader64 optionalHeader;
    readonly ImageFileHeader fileHeader;
    readonly ImageExportDirectory exportDirectory;

    public nint GetExportFunctionAddress(ReadOnlySpan<byte> name) => PEBase + (nint)GetEATFunction(name);

    uint GetEATFunction(ReadOnlySpan<byte> targetName)
    {
        var index = GetEATFunctionIndex(targetName);
        if (index == -1)
            return 0;
        else
            return Interop.ReadProcessMemory<uint>(
                ProcessHandle, 
                PEBase + 
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
                PEBase + 
                + (nint)exportDirectory.AddressOfNames
                + (nint)i * sizeof(uint)
            );
            var name = PEBase + (nint)nameRva;
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