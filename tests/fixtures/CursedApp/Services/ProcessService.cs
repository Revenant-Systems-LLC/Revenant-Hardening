using System.Diagnostics;
using System.Reflection;
using Microsoft.Win32;

namespace CursedApp.Services;

// RSH-EXEC-001: Process.Start with non-literal argument
// RSH-EXEC-002: UseShellExecute = true
// RSH-EXEC-003: Assembly.LoadFrom with non-literal path
// RSH-EXEC-004: URI handler registration
public class ProcessService
{
    public void OpenFile(string userProvidedPath)
    {
        // RSH-EXEC-001 + RSH-EXEC-002
        var psi = new ProcessStartInfo
        {
            FileName = userProvidedPath,
            UseShellExecute = true
        };
        Process.Start(psi);
    }

    public void RunTool(string toolName)
    {
        // RSH-EXEC-001
        Process.Start(toolName);
    }

    public void LoadPlugin(string pluginPath)
    {
        // RSH-EXEC-003
        var asm = Assembly.LoadFrom(pluginPath);
        var type = asm.GetType("Plugin.Main");
        type?.GetMethod("Run")?.Invoke(null, null);
    }

    public void RegisterUriHandler()
    {
        // RSH-EXEC-004
        using var key = Registry.ClassesRoot.OpenSubKey(@"cursedapp\shell\open\command", true);
        key?.SetValue("", $"\"{Environment.ProcessPath}\" \"%1\"");
        Registry.SetValue(@"HKEY_CLASSES_ROOT\cursedapp", "URL Protocol", "");
    }
}
