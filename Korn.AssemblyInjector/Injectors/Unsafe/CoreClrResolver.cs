using Korn.Utils.PEImageReader;
using Korn.Utils.UnsafePDBResolver;
using System.Net;

namespace Korn.AssemblyInjector;
internal unsafe class CoreClrResolver : IDisposable
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
        PEImage = new PEImage(module.Path);

        var debugSymbolsPath = ResolveDebugSymbols(module.Path);
        PdbResolver = new PdbResolver(debugSymbolsPath);
    }

    public readonly nint ProcessHandle;
    public readonly ProcessModulesResolver ModulesResolver;
    public readonly PdbResolver PdbResolver;
    public readonly PEImage PEImage;
    public readonly nint CoreClrHandle;

    string ResolveDebugSymbols(string modulePath)
    {
        var debugSymbolsPath = PdbResolver.GetDebugSymbolsPathForExecutable(modulePath);
        if (!File.Exists(debugSymbolsPath))
            DownloadDebugSymbols(modulePath, debugSymbolsPath);

        return debugSymbolsPath;
    }

    void DownloadDebugSymbols(string modulePath, string debugSymbolsPath)
    {
        var pdbPath = PdbResolver.GetDebugSymbolsPathForExecutable(modulePath);
        var debugInfo = PEImage.ReadDegubInfo();
        if (debugInfo is null)
            throw new KornError([
                "UnsafeInjector.CoreClrResolver->DownloadDebugSymbols:",
                    $"Failed to get coreClr module's debug informationю"
            ]);

        var downloadUrl = debugInfo.GetMicrosoftDebugSymbolsCacheUrl();
        try
        {
            KornLogger.WriteMessage($"Start downloading debug symbols from microsoft server for a file \"{modulePath}\" from ulr \"{downloadUrl}\"");
            new WebClient().DownloadFile(downloadUrl, debugSymbolsPath);
        }
        catch (Exception ex)
        {
            throw new KornException("UnsafeInjector.CoreClrResolver->DownloadDebugSymbols: Exception thrown when downloading debug symbols from microsoft server", ex);
        }
    }

    nint ResolveField(string fieldName, string declaringType)
    {
        var symbol = PdbResolver.ResolveField(fieldName, declaringType);

        var sector = PEImage.GetSectionByNumber(symbol->Segment);
        var offset = sector->VirtualAddress + symbol->SegmentOffset;

        return (nint)(CoreClrHandle + offset);
    }

    nint ResolveMethod(string methodName)
    {
        var symbol = PdbResolver.ResolveMethod(methodName);

        return (nint)(CoreClrHandle + 0x1000/*header size*/ + symbol->HeaderOffset);
    }

    public nint ResolveAppDomainAddress() => ResolveField("m_pTheAppDomain", "AppDomain");
    public nint ResolveSetupThread() => ResolveMethod("SetupThread");
    public nint ResolveInitializeAssemblyLoadContext() => ResolveMethod("AssemblyNative_InitializeAssemblyLoadContext");
    public nint ResolveLoadFromPath() => ResolveMethod("AssemblyNative_LoadFromPath");
    public nint ResolveExecuteMainMethod() => ResolveMethod("Assembly::ExecuteMainMethod");
    public nint ResolveRemoveThread() => ResolveMethod("ThreadStore::RemoveThread");

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;

        PdbResolver.Dispose();
    }

    ~CoreClrResolver() => Dispose();
}