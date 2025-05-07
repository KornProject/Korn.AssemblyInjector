using Korn.Utils.Assembler;
using System.Reflection;
using System.Text;
using Korn.Utils;
using Korn.AssemblyInjection;

#pragma warning disable CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type
namespace Korn;
public unsafe class AssemblyInjector : IDisposable
{
    static ulong 
        coreclr_footprint = ExternalProcessModules.GetNameFootprint("coreclr.dll"),
        clr_footprint = ExternalProcessModules.GetNameFootprint("clr.dll");

    public AssemblyInjector(int pid)
    {
        processId = new ExternalProcessId(pid);
        process = processId.Process;
        modules = processId.Modules;
        memory = process.Memory;

        coreclrModule = modules.FastGetModule(coreclr_footprint);
        if (!coreclrModule.IsValid)
            clrModule = modules.FastGetModule(clr_footprint);
    }

    ExternalProcessId processId;
    ExternalProcessModules modules;
    ExternalProcess process;
    ExternalMemory memory;
    ExternalProcessModule coreclrModule;
    ExternalProcessModule clrModule;

    public bool IsCoreClr => coreclrModule.IsValid;
    public bool IsClr => clrModule.IsValid;

    public void Inject(string path)
    {
        if (IsCoreClr)
            InjectInCoreClr(path);
        else if (IsClr)
            InjectInClr(path);
        else
            throw new KornError([
                "UnsafeInjector->.Inject: ",
                "Not found any VM in the target process."
            ]);
    }

    public void InjectInClr(string path)
    {
        if (!IsClr)
            throw new KornError([
                "UnsafeInjector->.InjectInClr: ",
                "Not found CLR in the target process."
            ]);

        using var clrResolver = new ClrResolver(memory, clrModule);
        var setupThreadFunction = clrResolver.ResolveSetupThread();
        var loadAssemblyFunction = clrResolver.ResolveLoadAssembly();
        var executeAssemblyFunction = clrResolver.ResolveExecuteAssembly();
        var removeThreadFunction = clrResolver.ResolveRemoveThread();

        var systemDomainPointer = clrResolver.ResolveSystemDomainAddress();
        var systemDomain = memory.Read<nint>(systemDomainPointer);
        var appDomain = memory.Read<nint>(systemDomain + 0x560);

        var allocatedMemory = AllocateMemory();
        var data = allocatedMemory;

        var codeBase = AllocateString(&allocatedMemory, path);
        var assemblyName = AllocateAssemblyName(&allocatedMemory, codeBase);

        var stackMark = allocatedMemory;
        memory.Write(stackMark, 1);
        allocatedMemory += 0x08;

        var exposedAppDomain = AllocateExposedAppDomain(&allocatedMemory, appDomain);

        var args = AllocateArgs(&allocatedMemory);

        var code = allocatedMemory;
        var shellcode = stackalloc byte[1024];
        var shellcodePointer = shellcode;
                
        var endShellcode = 
        ((Assembler*)&shellcodePointer)

        ->MovR1464(exposedAppDomain)
        ->MovR13Rsp()
        ->MovRbxRcx()
        ->MovRax64(setupThreadFunction)
        ->CallRax()
        ->MovR12Rax()
        
        ->MovRcx64(assemblyName)
        ->MovRdx64(codeBase)
        ->XorR9R9()
        ->XorR8R8()

        ->SubRsp8(0x48)
        ->MovRax64(stackMark)
        ->MovRspPtrOff8Rax(0x20)
        ->MovRspPtrOff832(0x28, 0)
        ->MovRspPtrOff832(0x30, 1)
        ->MovRspPtrOff832(0x38, 0)
        ->MovRspPtrOff832(0x40, 1)
        ->MovRax64(loadAssemblyFunction)
        ->CallRax()

        ->MovRcxR14()
        ->MovRdxRax()
        ->MovR964(args)
        ->MovRax64(executeAssemblyFunction)
        ->CallRax()

        ->MovRcxR12()
        ->MovRax64(removeThreadFunction)
        ->CallRax()

        ->MovRspR13()
        ->Ret();

        memory.Write(allocatedMemory, shellcode, (int)(*(byte**)endShellcode - shellcode));

        process.CreateThread(code, data);

        nint AllocateString(nint* addressPointer, string text)
        {
            var address = *addressPointer;
            var size = sizeof(nint) + sizeof(int) + text.Length * 2;
            *addressPointer += size;

            memory.Write(address, *(byte**)&text, size); /* unsafe */

            return address;
        }

        nint AllocateAssemblyName(nint* addressPointer, nint codeBase)
        {
            var address = *addressPointer;

            var size = SizeOf<AssemblyName>();
            *addressPointer += size;

            WriteCodeBase(codeBase);
            return address;

            void WriteCodeBase(nint name) => memory.Write(address + 0x28, (byte*)&name, sizeof(nint));
        }

        nint AllocateArgs(nint* memory)
        {
            var address = *memory;

            var size = 0x18;
            *memory += size;

            return address;
        }

        nint AllocateExposedAppDomain(nint* addressPointer, nint appDomain)
        {
            var address = *addressPointer;

            var size = 0xC8;
            *addressPointer += size;

            WriteAppDomain(appDomain);
            return address;

            void WriteAppDomain(nint appDomain) => memory.Write(address + 0xC0, appDomain);
        }

        int SizeOf<T>() => *((int*)typeof(T).TypeHandle.Value + 1);
    }

    public void InjectInCoreClr(string path)
    {
        if (!IsCoreClr)
            throw new KornError([
                "UnsafeInjector->.InjectInCoreClr: ",
                "Not found CoreCLR in the target process."
            ]);

        // const uint MEM_RELEASE = 0x00008000;
        // const uint INFINITE = 0xFFFFFFFF;

        using var coreClrResolver = new CoreClrResolver(memory, coreclrModule);
        var setupThreadFunction = coreClrResolver.ResolveSetupThread();
        var initializeFunction = coreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadAssemblyFunction = coreClrResolver.ResolveLoadFromPath();
        var executeMainFunction = coreClrResolver.ResolveExecuteMainMethod();
        var removeThreadFunction = coreClrResolver.ResolveRemoveThread();

        var assemblyBinder = GetAssemblyBinder();

        var allocatedMemory = AllocateMemory();
        var data = allocatedMemory;
        var pathBytes = Encoding.Unicode.GetBytes(path);
        memory.Write(allocatedMemory, pathBytes);
        allocatedMemory += pathBytes.Length + 2;

        var localLoadedAssembly = allocatedMemory;
        allocatedMemory += 0x08;

        var localArgumentsArray = allocatedMemory;
        allocatedMemory += 0x18;

        var localArgumentsArrayPointer = allocatedMemory;
        memory.Write(localArgumentsArrayPointer, localArgumentsArray);
        allocatedMemory += 0x08;
               
        var code = allocatedMemory;
        var shellcode = stackalloc byte[1024];
        var shellcodePointer = shellcode;

        var endShellcode =
        ((Assembler*)&shellcodePointer)

        ->MovR1464(assemblyBinder)
        ->MovR13Rsp()
        ->MovRbxRcx()
        ->MovRax64(setupThreadFunction)
        ->CallRax()
        ->MovR12Rax()

        ->MovRcxR14()
        ->MovRdxRbx()
        ->XorR8R8()
        ->MovR964(localLoadedAssembly)
        ->MovRax64(loadAssemblyFunction)
        ->SubRsp8(8)
        ->CallRax()

        ->MovRax64(localLoadedAssembly)
        ->MovRaxRaxPtr()
        ->MovRaxRaxPtrOff8(0x20)
        ->MovRcxRaxPtr()
        ->MovRdx64(localArgumentsArrayPointer)
        ->XorR8R8()
        ->MovRax64(executeMainFunction)
        ->CallRax()

        ->MovRcxR12()
        ->MovRax64(removeThreadFunction)
        ->CallRax()

        ->MovRspR13()

        ->Ret();

        memory.Write(allocatedMemory, shellcode, (int)(*(byte**)endShellcode - shellcode));

        process.CreateThread(code, data);
        /* Removed for reasons of the second argument not working. See [Dec 12 #1] in Notes.txt */
        //Interop.WaitForSingleObject(threadID, INFINITE);
        //Interop.VirtualFreeEx(processHandle, allocatedMemory, 0x1000, MEM_RELEASE);

        // Offsets of structures may be change with different .net x.0.0 versions. Required tests
        // &TheAppDomain->RootAssembly->PEAssembly->HostAssembly->AssemblyBinder
        nint GetAssemblyBinder() =>
            memory.Read<nint>(
                memory.Read<nint>(
                    memory.Read<nint>(
                        memory.Read<nint>(
                            memory.Read<nint>(
                                coreClrResolver.ResolveAppDomainAddress()) + 0x590) + 0x20) + 0x38) + 0x20);
    }

    nint AllocateMemory(int size = 0x1000) => ExternalMemoryAllocator.Allocate(process.Handle, IntPtr.Zero, size);

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;

        processId.Dispose();
    }

    ~AssemblyInjector() => Dispose();
}
#pragma warning restore CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type