using Korn.AssemblyInjector;
using System.Diagnostics;

var process = Process.GetProcessesByName("ConsoleTest")[0];

var injector = new Injector(process);

injector.Inject(
    assemblyPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\x64\Release\net9.0-windows\Korn.Bootstrapper.dll",
    configPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\x64\Release\net9.0-windows\Korn.Bootstrapper.runtimeconfig.json",
    assemblyName: "Korn.Bootstrapper",
    classFullName: "Program",
    methodName: "ExternalMain"
);