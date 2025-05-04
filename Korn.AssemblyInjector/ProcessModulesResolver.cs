using Korn.Utils.Unsafe;
using System.Text;

unsafe record ProcessModulesResolver(nint ProcessHandle)
{
    List<ProcessModule>? cachedResolvedModules;
    public List<ProcessModule> ResolveAllModules()
    {
        const int MAX_PATH = 1024;
        const int MAX_MODULES = 1024;

        List<ProcessModule> result = [];

        nint* modules = stackalloc nint[MAX_MODULES];
        var stringBuilder = new StringBuilder(MAX_PATH);

        int size;
        Interop.EnumProcessModules(ProcessHandle, modules, sizeof(nint) * MAX_MODULES, &size);
        
        for (var moduleIndex = 0; moduleIndex < size / sizeof(nint); moduleIndex++)
        {
            var moduleHandle = modules[moduleIndex];

            Interop.GetModuleFileNameEx(ProcessHandle, moduleHandle, stringBuilder, stringBuilder.Capacity);

            var name = Path.GetFileName(stringBuilder.ToString());
            var module = new ProcessModule(ProcessHandle, moduleHandle, name);
            result.Add(module);
        }

        cachedResolvedModules = result;
        return result;  
    }

    public ProcessModule? ResolveModule(string name)
    {
        if (cachedResolvedModules is null)
            ResolveAllModules();

        var modules = cachedResolvedModules;

        foreach (var module in modules!)
            if (string.Equals(name, module.Name, StringComparison.OrdinalIgnoreCase))
                return module;

        return null;
    }
}

unsafe record ProcessModule(nint ProcessHandle, nint ModuleHandle, string Name) 
{
    ModuleExportsResolver? exportsResolver;
    ModuleExportsResolver ExportsResolver => exportsResolver is null ? exportsResolver = new(this) : exportsResolver;

    public nint ResolveExport(string name) => ExportsResolver.ResolveExport(name);

    class ModuleExportsResolver
    {
        public ModuleExportsResolver(ProcessModule module)
        {
            Module = module;
            pe = new(module.ProcessHandle, module.ModuleHandle);
        }

        public readonly ProcessModule Module;
        RuntimePE pe;

        public nint ResolveExport(string name) => ResolveExport(new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(name)));
        public nint ResolveExport(NativeString* name) => ResolveExport(name->GetUtf8Span());
        public nint ResolveExport(ReadOnlySpan<byte> name) => pe.GetExportFunctionAddress(name);
    }
}