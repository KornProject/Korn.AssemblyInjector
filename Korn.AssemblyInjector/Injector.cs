using System.Diagnostics;

namespace Korn.AssemblyInjector;
public class Injector : IDisposable
{
    public Injector(Process process)
    {
        Process = process;
    }

    public readonly Process Process;

    nint unmanagedProcessHandle;
    public void Inject(string assemblyPath)
    {
        const int PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;
        var processHandle = Interop.OpenProcess(PROCESS_ALL_ACCESS, false, Process.Id);
        unmanagedProcessHandle = processHandle;

        var memoryBlob = MemoryBlob.Allocate(processHandle);


    }

    bool disposed;
    public void Dispose()
    {
        if (disposed)
            return;

        if (unmanagedProcessHandle != 0)
            Interop.CloseHandle(unmanagedProcessHandle);    
    }

    ~Injector() => Dispose();
}