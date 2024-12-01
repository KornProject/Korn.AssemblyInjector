using System.Runtime.InteropServices;
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

            var path = stringBuilder.ToString();
            var name = Path.GetFileNameWithoutExtension(path);
            var nameWithExtension = Path.GetFileName(path);
            var module = new ProcessModule(ProcessHandle, moduleHandle, path, name, nameWithExtension);
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
            if (string.Equals(name, module.NameWithExtension, StringComparison.OrdinalIgnoreCase))
                return module;

        foreach (var module in modules!)
            if (string.Equals(name, module.Name, StringComparison.OrdinalIgnoreCase))
                return module;

        return null;
    }
}

unsafe record ProcessModule(nint ProcessHandle, nint ModuleHandle, string Path, string Name, string NameWithExtension) 
{
    ModuleExportsResolver? exportsResolver;
    public nint ResolveExport(string name)
    {
        if (exportsResolver is null)
            exportsResolver = new(this);

        return exportsResolver.ResolveExport(name);
    }

    class ModuleExportsResolver
    {
        public ModuleExportsResolver(ProcessModule module)
        {
            Module = module;
            PE = new(module.ProcessHandle, module.ModuleHandle);
        }

        public readonly ProcessModule Module;
        readonly RuntimePE PE;

        public nint ResolveExport(string name) => ResolveExport(new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(name)));

        public nint ResolveExport(ReadOnlySpan<byte> name) => PE.GetExportFunctionAddress(name);
    }
}