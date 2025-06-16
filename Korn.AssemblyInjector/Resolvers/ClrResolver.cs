using Korn.Utils;

namespace Korn.AssemblyInjection;
internal unsafe class ClrResolver : LibraryResolver
{
    public ClrResolver(ProcessMemory memory, ProcessModule module) : base(memory, module) { }

    public nint ResolveSystemDomainAddress() => Resolve("m_pSystemDomain", "SystemDomain");
    public nint ResolveSetupThread() => Resolve("SetupThread");
    public nint ResolveLoadAssembly() => Resolve("Load", "AssemblyNative");
    public nint ResolveExecuteAssembly() => Resolve("ExecuteAssembly", "AppDomainNative");
    public nint ResolveRemoveThread() => Resolve("RemoveThread", "ThreadStore");
}