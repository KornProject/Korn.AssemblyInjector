using Korn.Utils.Logger;
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
        var setupThreadFunctionAddress = CoreClrResolver.ResolveSetupThread();
        var initializeFunctionAddress = CoreClrResolver.ResolveInitializeAssemblyLoadContext();
        var loadFunctionAddress = CoreClrResolver.ResolveLoadFromPath();
        var tlsIndexAddress = CoreClrResolver.ResolveTlsIndexAddress();
        var tlsIndex = Interop.ReadProcessMemory<byte>(processHandle, tlsIndexAddress);

        var allocatedMemory = Interop.VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        var data = allocatedMemory;
        var pathBytes = Encoding.Unicode.GetBytes(path);
        Interop.WriteProcessMemory(processHandle, allocatedMemory, pathBytes);
        allocatedMemory += pathBytes.Length + 2;

        var locals = allocatedMemory;
        var loaderContextAddress = locals;
        allocatedMemory += 8;

        var code = allocatedMemory;

        /*
         mov rbx,rcx
         mov rax,FFFFFFFFFFFFFFFF
         call rax
         mov rcx,0
         mov rdx,0
         mov r8,0
         mov rax,FFFFFFFFFFFFFFFF
         call rax
         mov rcx,rax
         mov rdx,rbx
         mov r8,0
         mov r9,FFFFFFFFFFFFFFFF
         mov rax,FFFFFFFFFFFFFFFF
         call rax
         ret 
        */

        byte[] shellcode = 
        [
            0x48, 0x89, 0xCB,
            0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax
            0xFF, 0xD0, // call rax
            0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax
            0xFF, 0xD0, // call rax
            0x48, 0x89, 0xC1,
            0x48, 0x89, 0xDA,
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x49, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 4-th arg
            0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax
            0x48, 0x83, 0xEC, 0x08, 
            0xFF, 0xD0, // call rax
            0x48, 0x83, 0xC4, 0x08,
            //0xC3 // ret
            0xEB, 0xFE // self jump
        ];
        Interop.WriteProcessMemory(processHandle, allocatedMemory, shellcode);  

        allocatedMemory += 3 + 2;
        Interop.WriteProcessMemory(processHandle, allocatedMemory, BitConverter.GetBytes(setupThreadFunctionAddress));

        allocatedMemory += 8 + 2 + 7 + 7 + 7 + 2;
        Interop.WriteProcessMemory(processHandle, allocatedMemory, BitConverter.GetBytes(initializeFunctionAddress));

        allocatedMemory += 8 + 2 + 3 + 3 + 7 + 2;
        Interop.WriteProcessMemory(processHandle, allocatedMemory, BitConverter.GetBytes(loaderContextAddress));

        allocatedMemory += 8 + 2;
        Interop.WriteProcessMemory(processHandle, allocatedMemory, BitConverter.GetBytes(loadFunctionAddress));

        allocatedMemory += shellcode.Length;

        var threadID = Interop.CreateRemoteThread(processHandle, 0, 0, code, data, 0, (nint*)0);
        Interop.WaitForSingleObject(threadID, INFINITE);
        Interop.VirtualFreeEx(processHandle, allocatedMemory, 0x1000, MEM_RELEASE);
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

        public nint ResolveInitializeAssemblyLoadContext()
        {
            const int offset = 0x130300;

            var address = CoreClrHandle + offset;

            var checkNumber = BitConverter.ToUInt64(Interop.ReadProcessMemory(ProcessHandle, address, 8));
            if (checkNumber != 0x49085B8949DC8B4CUL)
                throw new KornError([
                    "UnsafeInjector.CoreClrResolver->ResolveInitializeAssemblyLoadContext:",
                    "Used an incorrect offset to resolve function InitializeAssemblyLoadContext.",
                    "Most likely used an unsupported version of CoreClr, i.e. the .Net version.",
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
                    "Most likely used an unsupported version of CoreClr, i.e. the .Net version.",
                ]);

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
                    "Most likely used an unsupported version of CoreClr, i.e. the .Net version.",
                ]);

            return address;
        }

        public nint ResolveTlsIndexAddress()
        {
            const int offset = 0x4878E0;

            var address = CoreClrHandle + offset;
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