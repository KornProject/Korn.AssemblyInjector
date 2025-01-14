using System.Diagnostics;
using System.Reflection;
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
    public bool IsCoreClr => isCoreClr;

    public void Inject(string path)
    {
        if (isCoreClr)
            InjectInCoreClr(path);
        else InjectInClr(path);
    }

    public void InjectInClr(string path)
    {
        using var clrResolver = new ClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = clrResolver.ResolveSetupThread();
        var loadAssemblyFunction = clrResolver.ResolveLoadAssembly();
        var executeAssemblyFunction = clrResolver.ResolveExecuteAssembly();
        var removeThreadFunction = clrResolver.ResolveRemoveThread();

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

        /*
         mov r14,---
         mov r13,[rsp]
         mov rbx,rcx
         mov rax,<coreclr.SetupThread>
         call rax
         mov r12,rax
         
         mov rcx,---
         mov rdx,---
         xor r9,r9
         xor r10,r10

         sub rsp,0x48
         mov rax,---
         mov [rsp+0x20],rax
         mov [rsp+0x28],0
         mov [rsp+0x30],1
         mov [rsp+0x38],0
         mov [rsp+0x40],1       

         mov rax,---
         call rax
         mov rcx,r14
         mov rdx,rax
         mov r9,--- 
         mov rax,---
         call rax

         mov rcx,r12
         mov rax,<coreclr.RemoveThread>
         call rax
         mov [rsp],r13
         ret 
        */
        var code = allocatedMemory;
        byte[] shellcode =
        [
            0x49, 0xBE, ..BitConverter.GetBytes(exposedAppDomain),
            0x49, 0x89, 0xE5,
            //0x4C, 0x8B, 0x2C, 0x24,
            0x48, 0x89, 0xCB,
            0x48, 0xB8, ..BitConverter.GetBytes(setupThreadFunction),
            0xFF, 0xD0,
            0x49, 0x89, 0xC4,

            0x48, 0xB9, ..BitConverter.GetBytes(assemblyName),
            0x48, 0xBA, ..BitConverter.GetBytes(codeBase),
            0x4D, 0x31, 0xC9,
            0x4D, 0x31, 0xC0,

            0x48, 0x83, 0xEC, 0x48,
            0x48, 0xB8, ..BitConverter.GetBytes(stackMark),
            0x48, 0x89, 0x44, 0x24, 0x20,
            0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0x44, 0x24, 0x30, 0x01, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00,   
            0x48, 0xC7, 0x44, 0x24, 0x40, 0x01, 0x00, 0x00, 0x00,

            0x48, 0xB8, ..BitConverter.GetBytes(loadAssemblyFunction),
            0xFF, 0xD0,
            0x4C, 0x89, 0xF1,
            0x48, 0x89, 0xC2,
            0x49, 0xB9, ..BitConverter.GetBytes(args),
            0x48, 0xB8, ..BitConverter.GetBytes(executeAssemblyFunction),
            0xFF, 0xD0,

            0x4C, 0x89, 0xE1,
            0x48, 0xB8, ..BitConverter.GetBytes(removeThreadFunction),
            0xFF, 0xD0,
            0x4C, 0x89, 0xEC,
            //0x4C, 0x89, 0x2C, 0x24,
            0xC3
        ];

        Interop.WriteProcessMemory(processHandle, allocatedMemory, shellcode);  

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

            void WriteName(nint name) => Interop.WriteProcessMemory(processHandle, address + 0x8, (byte*)&name, sizeof(nint));
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
        const uint MEM_RELEASE = 0x00008000;
        const uint INFINITE = 0xFFFFFFFF;

        using var coreClrResolver = new CoreClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = coreClrResolver.ResolveSetupThread();
        var initializeFunction = coreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadAssemblyFunction = coreClrResolver.ResolveLoadFromPath();
        var executeMainFunction = coreClrResolver.ResolveExecuteMainMethod();
        var removeThreadFunction = coreClrResolver.ResolveRemoveThread();

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
            0x49, 0x89, 0xE5,
            //0x4C, 0x8B, 0x2C, 0x24,
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
            0x4C, 0x89, 0xEC,
            //0x4C, 0x89, 0x2C, 0x24,
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