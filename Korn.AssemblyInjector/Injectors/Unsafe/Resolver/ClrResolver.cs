namespace Korn.AssemblyInjector;
internal unsafe class ClrResolver : LibraryResolver
{
    public ClrResolver(nint processHandle) : base("clr", processHandle, new(processHandle)) { }
    public ClrResolver(nint processHandle, ProcessModulesResolver modulesResolver) : base("clr", processHandle, modulesResolver) { }

    public nint ResolveSystemDomainAddress() => Resolve("m_pSystemDomain", "SystemDomain");
    public nint ResolveSetupThread() => Resolve("SetupThread");
    public nint ResolveLoadAssembly() => Resolve("Load", "AssemblyNative");
    public nint ResolveExecuteAssembly() => Resolve("ExecuteAssembly", "AppDomainNative");
    public nint ResolveRemoveThread() => Resolve("RemoveThread", "ThreadStore");
}