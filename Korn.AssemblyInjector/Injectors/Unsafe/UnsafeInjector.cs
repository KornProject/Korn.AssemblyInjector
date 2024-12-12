using Korn.Utils.Logger;
using System;
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

    public void Inject(string path)
    {
        if (isCoreClr)
            InjectInCoreClr(path);
        else InjectInClr(path);
    }

    void InjectInClr(string path)
    {

    }

    void InjectInCoreClr(string path)
    {
        const int MEM_COMMIT = 0x1000;
        const int PAGE_EXECUTE_READWRITE = 0x40;
        const uint MEM_RELEASE = 0x00008000;
        const uint INFINITE = 0xFFFFFFFF;

        var CoreClrResolver = new CoreClrResolver(processHandle, modulesResolver);
        var setupThreadFunction = CoreClrResolver.ResolveSetupThread();
        var initializeFunction = CoreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadAssemblyFunction = CoreClrResolver.ResolveLoadFromPath();
        var executeMainFunction = CoreClrResolver.ResolveExecuteMainMethod();
        var removeThreadFunction = CoreClrResolver.ResolveRemoveThread();

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
        Interop.WaitForSingleObject(threadID, INFINITE);
        Interop.VirtualFreeEx(processHandle, allocatedMemory, 0x1000, MEM_RELEASE);

        // &TheAppDomain->RootAssembly->PEAssembly->HostAssembly->AssemblyBinder
        nint GetAssemblyBinder() =>
            Interop.ReadProcessMemory<nint>(processHandle, 
                Interop.ReadProcessMemory<nint>(processHandle,
                    Interop.ReadProcessMemory<nint>(processHandle,
                        Interop.ReadProcessMemory<nint>(processHandle, 
                            Interop.ReadProcessMemory<nint>(processHandle, 
                                CoreClrResolver.ResolveAppDomainAddress()) + 0x590) + 0x20) + 0x38) + 0x20);
    }

    public readonly Process Process;

    class CoreClrResolver
    {
        public CoreClrResolver(nint processHandle) : this(processHandle, new(processHandle)) { }

        public CoreClrResolver(nint processHandle, ProcessModulesResolver modulesResolver)
        {
            ProcessHandle = processHandle;
            ModulesResolver = modulesResolver;
            var module = ModulesResolver.ResolveModule("coreclr");
            if (module is null)
                throw new KornError([
                    "UnsafeInjector.CoreClrResolver->.ctor(nint, ProcessModulesResolver):",
                    $"CoreClr module not found in target process"
                ]);

            CoreClrHandle = module.ModuleHandle;
        }

        public readonly nint ProcessHandle;
        public readonly ProcessModulesResolver ModulesResolver;
        public readonly nint CoreClrHandle;
        const string UnsupportedVMVersionMessage = "Most likely used an unsupported version of CoreClr, i.e. the .Net version.";
        const string FunctionUnderDebbugerMessage = "Also maybe this function is currently under debugger, which prevents it from working correctly.";

        public nint ResolveAppDomainAddress()
        {
            const int offset = 0x488080;

            var address = CoreClrHandle + offset;
            // no check

            return address;
        }

        public nint ResolveSetupThread()
        {
            const int offset = 0x6BAE8;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x4155415756535540UL)
                throw new KornError([
                    "UnsafeInjector.CoreClrFunctionResolver->ResolveSetupThread:",
                    "Used an incorrect offset to resolve function SetupThread.",
                    UnsupportedVMVersionMessage,
                    FunctionUnderDebbugerMessage
                ]);

            return address;
        }

        public nint ResolveInitializeAssemblyLoadContext()
        {
            const int offset = 0x130300;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x49085B8949DC8B4CUL)
                throw new KornError([
                    "UnsafeInjector.CoreClrResolver->ResolveInitializeAssemblyLoadContext:",
                    "Used an incorrect offset to resolve function InitializeAssemblyLoadContext.",
                    UnsupportedVMVersionMessage,
                    FunctionUnderDebbugerMessage
                ]);

            return address;
        }

        public nint ResolveLoadFromPath()
        {
            const int offset = 0xF1320;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x49085B8949DC8B4CUL)
                throw new KornError([
                    "UnsafeInjector.CoreClrFunctionResolver->ResolveLoadFromPath:",
                    "Used an incorrect offset to resolve function LoadFromPath.",
                    UnsupportedVMVersionMessage,
                    FunctionUnderDebbugerMessage
                ]);

            return address;
        }

        public nint ResolveExecuteMainMethod()
        {
            const int offset = 0xF17C4;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x57565518245C8948)
                throw new KornError([
                    "UnsafeInjector.CoreClrFunctionResolver->ResolveExecuteMainMethod:",
                    "Used an incorrect offset to resolve function ExecuteMainMethod.",
                    UnsupportedVMVersionMessage,
                    FunctionUnderDebbugerMessage
                ]);

            return address;
        }        

        public nint ResolveRemoveThread()
        {
            const int offset = 0x622A8;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x8B4C20EC83485340UL)
                throw new KornError([
                    "UnsafeInjector.CoreClrFunctionResolver->ResolveRemoveThread:",
                    "Used an incorrect offset to resolve function RemoveThread.",
                    UnsupportedVMVersionMessage,
                    FunctionUnderDebbugerMessage
                ]);

            return address;
        }
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