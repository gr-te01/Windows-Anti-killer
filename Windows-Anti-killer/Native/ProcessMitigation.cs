using System;
using System.Runtime.InteropServices;
//ProcessMitigation.cs
namespace Windows_Anti_killer.Native
{
    internal static class ProcessMitigation
    {
        private const int ProcessExtensionPointDisablePolicy = 6;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
        {
            public uint Flags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessMitigationPolicy(
            int mitigationPolicy,
            ref PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY lpBuffer,
            nuint dwLength);

        public static bool EnableExtensionPointDisable()
        {
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY policy = new PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
            {
                Flags = 1
            };

            return SetProcessMitigationPolicy(
                ProcessExtensionPointDisablePolicy,
                ref policy,
                (nuint)Marshal.SizeOf<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>());
        }
    }
}