unsafe class RuntimePE
{
    public RuntimePE(nint processHandle, nint peBase)
    {
        ProcessHandle = processHandle;
        PEBase = peBase;

        e_lfanew = Interop.ReadProcessMemory<uint>(ProcessHandle, PEBase + 0x3C);
        optionalHeader = Interop.ReadProcessMemory<ImageOptionalHeader64>(ProcessHandle, PEBase + (nint)e_lfanew + 4 + 20);
        fileHeader = Interop.ReadProcessMemory<ImageFileHeader>(ProcessHandle, PEBase + (nint)e_lfanew + 4);
        sectionHeadersAddress = PEBase + (nint)e_lfanew + 4 + sizeof(ImageFileHeader) + fileHeader.SizeOfOptionalHeader;

        exportDirectoryRVA = optionalHeader.ExportTable.VirtualAddress;
        exportDirectorySize = optionalHeader.ExportTable.Size;
        exportDirectory = Interop.ReadProcessMemory<ImageExportDirectory>(ProcessHandle, PEBase + (nint)exportDirectoryRVA);

        eatOffset = RvaToFileOffset(exportDirectory.AddressOfFunctions);
        enptOffset = RvaToFileOffset(exportDirectory.AddressOfNames);
        eotOffset = RvaToFileOffset(exportDirectory.AddressOfNameOrdinals);

        _ = 3;
    }
    
    readonly nint ProcessHandle;
    readonly nint PEBase;
    readonly uint e_lfanew;
    readonly nint sectionHeadersAddress;
    readonly ImageOptionalHeader64 optionalHeader;
    readonly ImageFileHeader fileHeader;

    readonly uint exportDirectoryRVA;
    readonly uint exportDirectorySize;
    readonly ImageExportDirectory exportDirectory;

    readonly uint eatOffset;
    readonly uint enptOffset;
    readonly uint eotOffset;


    public uint GetExportFunctionAddress(ReadOnlySpan<byte> name) => GetEATFunction(name);

    uint GetEATFunction(ReadOnlySpan<byte> targetName)
    {
        var index = GetEATFunctionIndex(targetName);
        if (index == -1)
            return 0;
        else
            return Interop.ReadProcessMemory<uint>(ProcessHandle, PEBase + (nint)eatOffset + (nint)index * sizeof(uint));
    }

    long GetEATFunctionIndex(ReadOnlySpan<byte> targetName)
    {
        for (uint i = 0; i < exportDirectory.NumberOfNames; i++)
        {
            var nameRva = Interop.ReadProcessMemory<uint>(ProcessHandle, PEBase + (nint)enptOffset + (nint)i * sizeof(uint));
            var nameOffset = RvaToFileOffset(nameRva);
            var name = PEBase + (nint)nameOffset;
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

    uint RvaToFileOffset(uint rva)
    {
        for (int i = 0; i < fileHeader.NumberOfSections; i++)
        {
            var section = Interop.ReadProcessMemory<ImageSectionHeader>(ProcessHandle, sectionHeadersAddress + i * sizeof(ImageSectionHeader));
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
                return rva - section.VirtualAddress + section.PointerToRawData;
        }

        return 0;
    }
}