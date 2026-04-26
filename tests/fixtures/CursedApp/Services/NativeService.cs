using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace CursedApp.Services;

// RSH-PINVOKE-001: DllImport without CharSet=Unicode on string-param function
// RSH-PINVOKE-002: DllImport with non-literal DLL name
// RSH-PINVOKE-003: Dangerous impersonation API
// RSH-ACL-001: File.SetAccessControl
// RSH-ACL-002: FileSystemAccessRule with "Everyone"
public class NativeService
{
    private const string KernelDll = "kernel32.dll";

    // RSH-PINVOKE-001: no CharSet, has string parameter
    [DllImport("kernel32.dll")]
    private static extern bool CreateDirectory(string lpPathName, IntPtr lpSecurityAttributes);

    // RSH-PINVOKE-002: DLL name from variable, not a literal
    [DllImport(KernelDll)]
    private static extern IntPtr LoadLibraryDynamic(string lpLibFileName);

    // RSH-PINVOKE-003: privilege escalation API
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    // RSH-PINVOKE-003: impersonation API
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public int PrivilegeCount; public long Luid; public int Attributes; }

    public void GrantEveryoneAccess(string path)
    {
        // RSH-ACL-001: filesystem ACL modification
        var dirInfo = new System.IO.DirectoryInfo(path);
        var security = dirInfo.GetAccessControl();

        // RSH-ACL-002: FileSystemAccessRule with "Everyone"
        security.AddAccessRule(new FileSystemAccessRule(
            "Everyone",
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        dirInfo.SetAccessControl(security);
    }
}
