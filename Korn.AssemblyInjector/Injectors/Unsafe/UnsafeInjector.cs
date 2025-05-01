using Korn.Utils.Assembler;
using System.Diagnostics;
using System.Reflection;
using System.Text;

#pragma warning disable CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type
namespace Korn.AssemblyInjector;
public unsafe class UnsafeInjector : IDisposable
{
    public UnsafeInjector(Process process)
    {
        const int PROCESS_ALL_ACCESS = 0xF0000 | 0x100000 | 0xFFFF;

        Process = process;

        processHandle = Interop.OpenProcess(PROCESS_ALL_ACCESS, false, Process.Id);
        modulesResolver = new ProcessModulesResolver(processHandle);

        isCoreClr = modulesResolver.ResolveModule("coreclr") is not null;
        if (!isCoreClr)
            isClr = modulesResolver.ResolveModule("clr") is not null;
    }

    readonly ProcessModulesResolver modulesResolver;
    readonly nint processHandle;
    readonly bool isCoreClr;
    readonly bool isClr;

    public readonly Process Process;
    public bool IsCoreClr => isCoreClr;
    public bool IsClr => isClr;

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

        using var clrResolver = new ClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = clrResolver.ResolveSetupThread();
        var loadAssemblyFunction = clrResolver.ResolveLoadAssembly();
        var executeAssemblyFunction = clrResolver.ResolveExecuteAssembly();
        var removeThreadFunction = clrResolver.ResolveRemoveThread();
        var sleepFunction = clrResolver.ResolveSleep();

        var systemDomainPointer = clrResolver.ResolveSystemDomainAddress();
        var systemDomain = Interop.ReadProcessMemory<nint>(processHandle, systemDomainPointer);
        var appDomain = Interop.ReadProcessMemory<nint>(processHandle, systemDomain + 0x560);

        var allocatedMemory = AllocateMemory();
        var data = allocatedMemory;

        var codeBase = AllocateString(&allocatedMemory, path);
        var assemblyName = AllocateAssemblyName(&allocatedMemory, codeBase);

        var stackMark = allocatedMemory;
        Interop.WriteProcessMemory(processHandle, stackMark, BitConverter.GetBytes(1));
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

        ->MovRcx64(0xFFFFFFFF)
        ->MovRax64(sleepFunction)
        ->CallRax()

        ->Ret();

        Interop.WriteProcessMemory(processHandle, allocatedMemory, shellcode, (int)(*(byte**)endShellcode - shellcode));

        var threadID = Interop.CreateRemoteThread(processHandle, 0, 0, code, data, 0, (nint*)0);

        nint AllocateString(nint* memory, string text)
        {
            var address = *memory;
            var size = sizeof(nint) + sizeof(int) + text.Length * 2;
            *memory += size;
            Interop.WriteProcessMemory(processHandle, address, *(byte**)&text, size);

            return address;
        }

        nint AllocateAssemblyName(nint* memory, nint codeBase)
        {
            var address = *memory;

            var size = SizeOf<AssemblyName>();
            *memory += size;

            WriteCodeBase(codeBase);
            return address;

            void WriteCodeBase(nint name) => Interop.WriteProcessMemory(processHandle, address + 0x28, (byte*)&name, sizeof(nint));
        }

        nint AllocateArgs(nint* memory)
        {
            var address = *memory;

            var size = 0x18;
            *memory += size;

            return address;
        }

        nint AllocateExposedAppDomain(nint* memory, nint appDomain)
        {
            var address = *memory;

            var size = 0xC8;
            *memory += size;

            WriteAppDomain(appDomain);
            return address;

            void WriteAppDomain(nint appDomain) => Interop.WriteProcessMemory(processHandle, address + 0xC0, appDomain);
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

        using var coreClrResolver = new CoreClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = coreClrResolver.ResolveSetupThread();
        var initializeFunction = coreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadAssemblyFunction = coreClrResolver.ResolveLoadFromPath();
        var executeMainFunction = coreClrResolver.ResolveExecuteMainMethod();
        var removeThreadFunction = coreClrResolver.ResolveRemoveThread();
        var sleepFunction = coreClrResolver.ResolveSleep();

        var assemblyBinder = GetAssemblyBinder();

        var allocatedMemory = AllocateMemory();
        var data = allocatedMemory;
        var pathBytes = Encoding.Unicode.GetBytes(path);
        Interop.WriteProcessMemory(processHandle, allocatedMemory, pathBytes);
        allocatedMemory += pathBytes.Length + 2;

        var localLoadedAssembly = allocatedMemory;
        allocatedMemory += 0x08;

        var localArgumentsArray = allocatedMemory;
        allocatedMemory += 0x18;

        var localArgumentsArrayPointer = allocatedMemory;
        Interop.WriteProcessMemory(processHandle, localArgumentsArrayPointer, BitConverter.GetBytes(localArgumentsArray));
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

        ->MovRcx64(0xFFFFFFFF)
        ->MovRax64(sleepFunction)
        ->CallRax()

        ->Ret();

        Interop.WriteProcessMemory(processHandle, allocatedMemory, shellcode, (int)(*(byte**)endShellcode - shellcode));

        var threadID = Interop.CreateRemoteThread(processHandle, 0, 0, code, data, 0, (nint*)0);
        /* Removed for reasons of the second argument not working. See [Dec 12 #1] in Notes.txt */
        //Interop.WaitForSingleObject(threadID, INFINITE);
        //Interop.VirtualFreeEx(processHandle, allocatedMemory, 0x1000, MEM_RELEASE);

        // Offsets of structures may be change with different .net x.0.0 versions. Required tests
        // &TheAppDomain->RootAssembly->PEAssembly->HostAssembly->AssemblyBinder
        nint GetAssemblyBinder() =>
            Interop.ReadProcessMemory<nint>(processHandle,
                Interop.ReadProcessMemory<nint>(processHandle,
                    Interop.ReadProcessMemory<nint>(processHandle,
                        Interop.ReadProcessMemory<nint>(processHandle,
                            Interop.ReadProcessMemory<nint>(processHandle,
                                coreClrResolver.ResolveAppDomainAddress()) + 0x590) + 0x20) + 0x38) + 0x20);
    }

    nint AllocateMemory(int size = 0x1000)
    {
        const int MEM_COMMIT = 0x1000;
        const int PAGE_EXECUTE_READWRITE = 0x40;

        return Interop.VirtualAllocEx(processHandle, 0, (uint)size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;
        disposed = true;

        if (processHandle != 0)
            Interop.CloseHandle(processHandle);
    }

    ~UnsafeInjector() => Dispose();
}
#pragma warning restore CS8500 // This takes the address of, gets the size of, or declares a pointer to a managed type