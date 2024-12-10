using Korn.AssemblyInjector;
using System.Diagnostics;

var process = Process.GetProcessesByName("ConsoleTest")[0];

using var injector = new UnsafeInjector(process);

injector.Inject(@"C:\Data\programming\vs projects\repos\ConsoleTest\TestLibrary\bin\Debug\net8.0\TestLibrary.dll");

/*
var injector = new HostfxrInjector(
    process,
    @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\x64\hostfxr.dll"
);
*/

/*
injector.Inject(
    hostfxrPath: @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\x64\hostfxr.dll",
    assemblyPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\Debug\net8.0-windows\Korn.Bootstrapper.dll",
    configPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\Debug\net8.0-windows\Korn.Bootstrapper.runtimeconfig.json",
    assemblyName: "Korn.Bootstrapper",
    classFullName: "Program",
    methodName: "ExternalMain"
);
*/

/*
injector.Inject(
    assemblyPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper.netcore\bin\Debug\netcoreapp3.1\Korn.Bootstrapper.netcore.dll",
    configPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper.netcore\bin\Debug\netcoreapp3.1\Korn.Bootstrapper.netcore.runtimeconfig.json",
    assemblyName: "Korn.Bootstrapper.netcore",
    classFullName: "Program",
    methodName: "ExternalMain"
);
*/

/*
injector.Inject(
    hostfxrPath: @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\x64\hostfxr.dll",
    assemblyPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper (.netcore) (works)\bin\Debug\netcoreapp3.1\Korn.Bootstrapper.dll",
    configPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper (.netcore) (works)\bin\Debug\netcoreapp3.1\Korn.Bootstrapper.runtimeconfig.json",
    assemblyName: "Korn.Bootstrapper",
    classFullName: "Program",
    methodName: "ExternalMain"
);
*/

/*
injector.Inject(
    hostfxrPath: @"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\SdkResolvers\Microsoft.DotNet.MSBuildSdkResolver\x64\hostfxr.dll",
    assemblyPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\Debug\net9.0\Korn.Bootstrapper.dll",
    configPath: @"C:\Data\programming\vs projects\korn\Korn.Bootstrapper\Korn.Bootstrapper\bin\Debug\net9.0\Korn.Bootstrapper.runtimeconfig.json",
    assemblyName: "Korn.Bootstrapper",
    classFullName: "Program",
    methodName: "ExternalMain"
);
*/