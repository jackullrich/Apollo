using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ApolloInterop.Utils
{
    public static class RegistryUtils
    {
        [DllImport("advapi32.dll")]
        private static extern int RegOpenCurrentUser(int samDesired, out SafeRegistryHandle keyHandle);

        [DllImport("advapi32.dll")]
        private static extern int RegOpenUserClassesRoot(IntPtr token, int options, int samDesired, out SafeRegistryHandle keyHandle);

        public static RegistryKey GetRegistryKey(string hive, string subkey, bool forWriting)
        {
            RegistryKey regKey;
            switch (hive)
            {
                case "HKU":
                    regKey = Registry.Users.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCC":
                    regKey = Registry.CurrentConfig.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCU":
                    regKey = OpenUserKey(hive, subkey, forWriting);
                    break;
                case "HKLM":
                    regKey = Registry.LocalMachine.OpenSubKey(subkey, forWriting);
                    break;
                case "HKCR":
                    regKey = OpenUserKey(hive, subkey, forWriting);
                    break;
                default:
                    throw new Exception($"Unknown registry hive: {hive}");
            }
            return regKey;
        }

        private static RegistryKey OpenUserKey(string hive, string subkey, bool forWriting)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                // RegOpenCurrentUser can fall back to the default hive when the profile is absent.
                // Fail explicitly rather than reading or writing another user's registry data.
                using (RegistryKey profile = identity.User == null ? null : Registry.Users.OpenSubKey(identity.User.Value))
                {
                    if (profile == null)
                        throw new InvalidOperationException("The current user's registry profile is not loaded.");
                }

                // Predefined HKCU/HKCR handles are process-wide; these APIs select the thread's user.
                // https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regopencurrentuser
                // https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regopenuserclassesroot
                SafeRegistryHandle rootHandle;
                int error = hive == "HKCU"
                    ? RegOpenCurrentUser((int)RegistryRights.ReadKey, out rootHandle)
                    : RegOpenUserClassesRoot(identity.Token, 0, (int)RegistryRights.ReadKey, out rootHandle);
                using (rootHandle)
                {
                    if (error != 0)
                        throw new Win32Exception(error);

                    using (RegistryKey root = RegistryKey.FromHandle(rootHandle))
                    {
                        return root.OpenSubKey(subkey, forWriting);
                    }
                }
            }
        }
    }
}
