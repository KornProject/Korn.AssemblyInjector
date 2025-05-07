using Korn.Utils;

namespace Korn.AssemblyInjection;
internal unsafe class CoreClrResolver : LibraryResolver
{
    public CoreClrResolver(ExternalMemory memory, ExternalProcessModule module) : base(memory, module) { }

    public nint ResolveAppDomainAddress() => Resolve("m_pTheAppDomain", "AppDomain");
    public nint ResolveSetupThread() => Resolve("SetupThread");
    public nint ResolveInitializeAssemblyLoadContext() => Resolve("AssemblyNative_InitializeAssemblyLoadContext");
    public nint ResolveLoadFromPath() => Resolve("AssemblyNative_LoadFromPath");
    public nint ResolveExecuteMainMethod() => Resolve("Assembly::ExecuteMainMethod");
    public nint ResolveRemoveThread() => Resolve("ThreadStore::RemoveThread");
}