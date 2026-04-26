using Microsoft.Win32;

namespace CursedApp.Services;

// RSH-REG-001: Registry.LocalMachine access
// RSH-REG-002: OpenSubKey with writable: true
// RSH-REG-003: HKLM write with no elevation guard
public class RegistryService
{
    public void WriteAppSetting(string key, string value)
    {
        var regKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\CursedApp", writable: true);
        regKey?.SetValue(key, value);
    }

    public string? ReadAppSetting(string key)
    {
        var regKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\CursedApp");
        return regKey?.GetValue(key)?.ToString();
    }

    public void RegisterApp()
    {
        using var hklm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\CursedApp", true);
        hklm?.SetValue("Installed", "true");
        hklm?.SetValue("Version", "1.0.0");
    }
}
