namespace Korn.AssemblyInjector;
internal unsafe class CoreClrResolver : LibraryResolver
{
    public CoreClrResolver(nint processHandle) : base("coreclr", processHandle, new(processHandle)) { }
    public CoreClrResolver(nint processHandle, ProcessModulesResolver modulesResolver) : base("coreclr", processHandle, modulesResolver) { }

    public nint ResolveAppDomainAddress() => Resolve("m_pTheAppDomain", "AppDomain");
    public nint ResolveSetupThread() => Resolve("SetupThread");
    public nint ResolveInitializeAssemblyLoadContext() => Resolve("AssemblyNative_InitializeAssemblyLoadContext");
    public nint ResolveLoadFromPath() => Resolve("AssemblyNative_LoadFromPath");
    public nint ResolveExecuteMainMethod() => Resolve("Assembly::ExecuteMainMethod");
    public nint ResolveRemoveThread() => Resolve("ThreadStore::RemoveThread");
}