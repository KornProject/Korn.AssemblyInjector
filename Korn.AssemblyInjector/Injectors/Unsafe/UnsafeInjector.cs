using System.Diagnostics;
using System.Text;

namespace Korn.AssemblyInjector;
public unsafe class UnsafeInjector : IDisposable
{
    public UnsafeInjector(Process process)
    {
        const int PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;

        Process = process;

        processHandle = Interop.OpenProcess(PROCESS_ALL_ACCESS, false, Process.Id);
        modulesResolver = new ProcessModulesResolver(processHandle);

        isCoreClr = modulesResolver.ResolveModule("coreclr") is not null;
        if (!isCoreClr)
        {
            var isClr = modulesResolver.ResolveModule("clr") is not null;
            if (!isClr)
                throw new KornError([
                    "UnsafeInjector->.ctor:",
                    "Not found any CLR in the target process"
                ]);
        }
    }

    readonly ProcessModulesResolver modulesResolver;
    readonly nint processHandle;
    readonly bool isCoreClr;

    public readonly Process Process;

    public void Inject(string path)
    {
        if (isCoreClr)
            InjectInCoreClr(path);
        else InjectInClr(path);
    }

    void InjectInClr(string path)
    {
        throw new NotImplementedException();
    }

    void InjectInCoreClr(string path)
    {
        const int MEM_COMMIT = 0x1000;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const uint MEM_RELEASE = 0x00008000;
        const uint INFINITE = 0xFFFFFFFF;

        using var coreClrResolver = new CoreClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = coreClrResolver.ResolveSetupThread();
        var initializeFunction = coreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadAssemblyFunction = coreClrResolver.ResolveLoadFromPath();
        var executeMainFunction = coreClrResolver.ResolveExecuteMainMethod();
        var removeThreadFunction = coreClrResolver.ResolveRemoveThread();

        var assemblyBinder = GetAssemblyBinder();

        var allocatedMemory = Interop.VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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

        /*
         mov r14,---
         mov r13,[rsp]
         mov rbx,rcx
         mov rax,<coreclr.SetupThread>
         call rax
         mov r12,rax
         mov rcx,r14
         mov rdx,rbx
         mov r8,0
         mov r9,---
         mov rax,<coreclr.LoadFromPath>
         sub rsp,8
         call rax
         mov rax,---
         mov rax,qword ptr ds:[rax]
         mov rax,qword ptr ds:[rax+20]
         mov rcx,qword ptr ds:[rax]
         mov rdx,---
         mov r8,0
         mov rax,<coreclr.ExecuteMainMethod>
         call rax
         mov rcx,r12
         mov rax,<coreclr.RemoveThread>
         call rax
         mov [rsp],r13
         ret 
        */
        byte[] shellcode = 
        [
            0x49, 0xBE, ..BitConverter.GetBytes(assemblyBinder),
            0x4C, 0x8B, 0x2C, 0x24,
            0x48, 0x89, 0xCB, 
            0x48, 0xB8, ..BitConverter.GetBytes(setupThreadFunction), 
            0xFF, 0xD0, 
            0x49, 0x89, 0xC4,
            0x4C, 0x89, 0xF1,
            0x48, 0x89, 0xDA,
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x49, 0xB9, ..BitConverter.GetBytes(localLoadedAssembly),
            0x48, 0xB8, ..BitConverter.GetBytes(loadAssemblyFunction),
            0x48, 0x83, 0xEC, 0x08,
            0xFF, 0xD0, 
            0x48, 0xB8, ..BitConverter.GetBytes(localLoadedAssembly),
            0x48, 0x8B, 0x00,
            0x48, 0x8B, 0x40, 0x20,
            0x48, 0x8B, 0x08,
            0x48, 0xBA, ..BitConverter.GetBytes(localArgumentsArrayPointer),
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 
            0x48, 0xB8, ..BitConverter.GetBytes(executeMainFunction),
            0xFF, 0xD0,
            0x4C, 0x89, 0xE1, 
            0x48, 0xB8, ..BitConverter.GetBytes(removeThreadFunction), 
            0xFF, 0xD0,
            0x4C, 0x89, 0x2C, 0x24,
            0xC3
        ];

        Interop.WriteProcessMemory(processHandle, allocatedMemory, shellcode);  

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

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;

        if (processHandle != 0)
            Interop.CloseHandle(processHandle);
    }

    ~UnsafeInjector() => Dispose();
}