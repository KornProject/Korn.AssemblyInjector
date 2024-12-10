using Korn.Utils.Logger;
using System.Diagnostics;
using System.Text;

namespace Korn.AssemblyInjector;
public unsafe class HostfxrInjector : IDisposable
{
    public HostfxrInjector(Process process, string? hostfxrPath)
    {
        const int PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;

        Process = process;
        HostfxrPath = hostfxrPath;

        processHandle = Interop.OpenProcess(PROCESS_ALL_ACCESS, false, Process.Id);
    }

    public readonly string? HostfxrPath;
    public readonly Process Process;

    readonly nint processHandle;
    public void Inject(string assemblyPath, string configPath, string assemblyName, string classFullName, string methodName)
    {
        const int HDT_LOAD_ASSEMBLY = 5;
        const uint INFINITE = 0xFFFFFFFF;

        if (!File.Exists(assemblyPath))
            throw new KornError(
                ["HostfxrInjector->Inject:", 
                $"Failed to find assembly file {Path.GetFileName(assemblyPath)}."]
            );  

        if (!File.Exists(configPath))
            throw new KornError(
                ["HostfxrInjector->Inject:",
                $"Failed to find config file {Path.GetFileName(configPath)}."]
            );

        var memoryBlob = MemoryBlob.Allocate(processHandle);
        var procedureBlob = memoryBlob.ExtractBlob(0, 2048);
        var dataBlob = new DataMemoryBlob(memoryBlob.ExtractBlob(2048, 2048));

        var moduleResolver = new ProcessModulesResolver(processHandle);
        var hostfxr = moduleResolver.ResolveModule("hostfxr");
        if (hostfxr is null)
        {
            if (HostfxrPath is null)
                throw new KornError(
                    ["HostfxrInjector->Inject:",
                    "Hostfxr module not found, load this module into the target application or specify the path to it in the constructor of the HostfxrInjerctor class"]);

            LoadLibrary(processHandle, HostfxrPath);
            moduleResolver.ResolveAllModules();
            hostfxr = moduleResolver.ResolveModule("hostfxr");
        }

        var hostfxr_initialize_for_runtime_config = hostfxr.ResolveExport("hostfxr_initialize_for_runtime_config");
        var hostfxr_get_runtime_delegate = hostfxr.ResolveExport("hostfxr_get_runtime_delegate");
        var hostfxr_close = hostfxr.ResolveExport("hostfxr_close");

        var assemblyPathData = dataBlob.AllocateWString(assemblyPath);
        var configPathData = dataBlob.AllocateWString(configPath);
        var typeData = dataBlob.AllocateWString($"{classFullName}, {assemblyName}");
        var methodData = dataBlob.AllocateWString(methodName);

        procedureBlob.FillBy(0x90);
        var assembler = new Assembler(procedureBlob);
        var procedure = new AssemblerProcedure(assembler,
            stackSize: 0x100,
            flags: ProcedureFlags.AllowStackValue64 | 
                   ProcedureFlags.ReserveAllArgRegisters
        );

        var var_assemblyPath = procedure.InitializeVariable(assemblyPathData);
        var var_configPath = procedure.InitializeVariable(configPathData);
        var var_type = procedure.InitializeVariable(typeData);
        var var_method = procedure.InitializeVariable(methodData);
        var var_hfxrInitRuntimeConfig = procedure.InitializeVariable(hostfxr_initialize_for_runtime_config);
        var var_hfxrGetRuntimeDelegate = procedure.InitializeVariable(hostfxr_get_runtime_delegate);
        var var_hfxrClose = procedure.InitializeVariable(hostfxr_close);
        var var_nullptr = procedure.InitializeVariable(nint.Zero);
        var var_ctx = procedure.CreateVariable<nint>();
        var var_ctxPointer = procedure.CreatePointerToVariable(var_ctx);
        var var_hdtConstant = procedure.InitializeVariable((long)HDT_LOAD_ASSEMBLY);
        var var_loader = procedure.CreateVariable<nint>();
        var var_loaderPointer = procedure.CreatePointerToVariable(var_loader);
        var var_entryPoint = procedure.CreateVariable<nint>();
        var var_entryPointPointer = procedure.CreatePointerToVariable(var_entryPoint);

        procedure.FastCallNoReturnPointer(
            var_hfxrInitRuntimeConfig,
            var_configPath,
            var_nullptr,
            var_ctxPointer
        );

        procedure.FastCallNoReturnPointer(
            var_hfxrGetRuntimeDelegate,
            var_ctx,
            var_hdtConstant,
            var_loaderPointer
        );

        procedure.FastCallNoReturnPointer(
            var_hfxrClose, 
            var_ctx
        );

        procedure.CallHostFxrStubNoReturnPointer(
            var_loader, 
            var_assemblyPath,
            var_type,
            var_method,
            var_nullptr,
            var_nullptr,
            var_entryPointPointer
        );

        procedure.FastCallNoReturnPointer(
            var_entryPoint,
            var_nullptr,
            var_nullptr
        );

        procedure.WriteEpilogue();

        var threadID = Interop.CreateRemoteThread(processHandle, 0, 0, procedure.Address, 0, 0, (nint*)0);
        Interop.WaitForSingleObject(threadID, INFINITE);
        memoryBlob.Free();

        Interop.CloseHandle(processHandle);
    }

    static void LoadLibrary(nint processHandle, string path)
    {
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RELEASE = 0x00008000;
        const uint PAGE_READWRITE = 0x04;
        const uint INFINITE = 0xFFFFFFFF;

        var kernelModule = Interop.GetModuleHandle("kernel32");
        var loadLibraryAddress = Interop.GetProcAddress(kernelModule, "LoadLibraryA");

        var allocatedMemory = Interop.VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        Interop.WriteProcessMemory(processHandle, allocatedMemory, Encoding.UTF8.GetBytes(path));
        var threadID = Interop.CreateRemoteThread(processHandle, 0, 0, loadLibraryAddress, allocatedMemory, 0, (nint*)0);
        Interop.WaitForSingleObject(threadID, INFINITE);
        Interop.VirtualFreeEx(processHandle, allocatedMemory, 0x1000, MEM_RELEASE);
    }

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;

        if (processHandle != 0)
            Interop.CloseHandle(processHandle);    
    }

    ~HostfxrInjector() => Dispose();
}