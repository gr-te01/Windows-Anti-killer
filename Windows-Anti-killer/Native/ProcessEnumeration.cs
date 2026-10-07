using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Windows_Anti_killer.Controller;

//ProcessEnumeration.cs
namespace Windows_Anti_killer.Native
{
    internal static class ProcessEnumeration
    {
        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private const int INVALID_HANDLE_VALUE = -1;

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;

        private const uint ERROR_INSUFFICIENT_BUFFER = 122;

        private const int ProcessProtectionLevelInfo = 7;

        private const uint PROTECTION_LEVEL_NONE = 0;

        private const uint SECURITY_MANDATORY_UNTRUSTED_RID = 0x0000;
        private const uint SECURITY_MANDATORY_LOW_RID = 0x1000;
        private const uint SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        private const uint SECURITY_MANDATORY_HIGH_RID = 0x3000;
        private const uint SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

        private enum TokenInformationClass
        {
            TokenUser = 1,
            TokenElevation = 20,
            TokenIntegrityLevel = 25
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {
            public uint TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_PROTECTION_LEVEL_INFORMATION
        {
            public uint ProtectionLevel;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(
            uint dwFlags,
            uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Process32FirstW(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Process32NextW(
            IntPtr hSnapshot,
            ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId);

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(
            IntPtr hProcess,
            uint dwFlags,
            StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport(
            "advapi32.dll",
            SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport(
            "advapi32.dll",
            SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern bool LookupAccountSidW(
            string? lpSystemName,
            IntPtr Sid,
            StringBuilder Name,
            ref uint cchName,
            StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out int peUse);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthorityCount(
            IntPtr pSid);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthority(
            IntPtr pSid,
            uint nSubAuthority);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        private static extern bool GetProcessInformation(
            IntPtr hProcess,
            int ProcessInformationClass,
            ref PROCESS_PROTECTION_LEVEL_INFORMATION ProcessInformation,
            uint ProcessInformationSize);

        internal static List<NativeProcessRecord> Enumerate()
        {
            List<NativeProcessRecord> results = new();

            IntPtr snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0);

            if (snapshot == new IntPtr(INVALID_HANDLE_VALUE))
            {
                throw new InvalidOperationException(
                    "无法创建进程快照。");
            }

            try
            {
                PROCESSENTRY32 entry = new PROCESSENTRY32
                {
                    dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>(),
                    szExeFile = string.Empty
                };

                if (!Process32FirstW(snapshot, ref entry))
                {
                    throw new InvalidOperationException(
                        "无法读取第一个进程条目。");
                }

                do
                {
                    results.Add(
                        ReadProcess(entry));
                }
                while (Process32NextW(snapshot, ref entry));
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return results;
        }

        // === 4.1 修改：ReadProcess 改为 值 + 状态 ===
        private static NativeProcessRecord ReadProcess(
            PROCESSENTRY32 entry)
        {
            string executablePath = string.Empty;
            ProcessFieldStatus executablePathStatus =
                ProcessFieldStatus.NotAvailable;

            string userName = string.Empty;
            ProcessFieldStatus userNameStatus =
                ProcessFieldStatus.NotAvailable;

            string integrityLevel = string.Empty;
            ProcessFieldStatus integrityLevelStatus =
                ProcessFieldStatus.NotAvailable;

            ProcessProtectionState protectionState =
                ProcessProtectionState.Unknown;

            ProcessFieldStatus protectionStateStatus =
                ProcessFieldStatus.NotAvailable;

            IntPtr processHandle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                entry.th32ProcessID);

            if (processHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();

                ProcessFieldStatus failureStatus =
                    GetFailureStatus(error);

                executablePathStatus = failureStatus;
                userNameStatus = failureStatus;
                integrityLevelStatus = failureStatus;
                protectionStateStatus = failureStatus;
            }
            else
            {
                try
                {
                    (
                        executablePath,
                        executablePathStatus
                    ) = TryGetExecutablePath(processHandle);

                    (
                        userName,
                        userNameStatus,
                        integrityLevel,
                        integrityLevelStatus
                    ) = TryGetTokenInformation(processHandle);

                    (
                        protectionState,
                        protectionStateStatus
                    ) = TryGetProtectionState(processHandle);
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }

            return new NativeProcessRecord
            {
                ProcessId = entry.th32ProcessID,

                ParentProcessId =
                    entry.th32ParentProcessID,

                Name =
                    entry.szExeFile ?? string.Empty,

                ExecutablePath =
                    executablePath,

                ExecutablePathStatus =
                    executablePathStatus,

                UserName =
                    userName,

                UserNameStatus =
                    userNameStatus,

                IntegrityLevel =
                    integrityLevel,

                IntegrityLevelStatus =
                    integrityLevelStatus,

                ProtectionState =
                    protectionState,

                ProtectionStateStatus =
                    protectionStateStatus
            };
        }

        // === 4.2 修改：TryGetExecutablePath 返回元组 ===
        private static (
            string Value,
            ProcessFieldStatus Status)
            TryGetExecutablePath(
                IntPtr processHandle)
        {
            StringBuilder buffer =
                new StringBuilder(32768);

            uint size =
                (uint)buffer.Capacity;

            if (!QueryFullProcessImageNameW(
                    processHandle,
                    0,
                    buffer,
                    ref size))
            {
                int error =
                    Marshal.GetLastWin32Error();

                return (
                    string.Empty,
                    GetFailureStatus(error));
            }

            return (
                buffer.ToString(),
                ProcessFieldStatus.Success);
        }

        // === 4.3 修改：TryGetTokenInformation 返回 4 元组 ===
        private static (
            string UserName,
            ProcessFieldStatus UserNameStatus,
            string IntegrityLevel,
            ProcessFieldStatus IntegrityLevelStatus)
            TryGetTokenInformation(
                IntPtr processHandle)
        {
            if (!OpenProcessToken(
                    processHandle,
                    TOKEN_QUERY,
                    out IntPtr tokenHandle))
            {
                int error =
                    Marshal.GetLastWin32Error();

                ProcessFieldStatus status =
                    GetFailureStatus(error);

                return (
                    string.Empty,
                    status,
                    string.Empty,
                    status);
            }

            try
            {
                (
                    string userName,
                    ProcessFieldStatus userNameStatus
                ) = ReadUserName(tokenHandle);

                (
                    string integrityLevel,
                    ProcessFieldStatus integrityLevelStatus
                ) = ReadIntegrityLevel(tokenHandle);

                return (
                    userName,
                    userNameStatus,
                    integrityLevel,
                    integrityLevelStatus);
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }

        // === 4.4 修改：ReadUserName 返回元组 ===
        private static (
            string Value,
            ProcessFieldStatus Status)
            ReadUserName(
                IntPtr tokenHandle)
        {
            if (!GetTokenInformation(
                    tokenHandle,
                    TokenInformationClass.TokenUser,
                    IntPtr.Zero,
                    0,
                    out uint requiredSize))
            {
                int error =
                    Marshal.GetLastWin32Error();

                if (error != ERROR_INSUFFICIENT_BUFFER ||
                    requiredSize == 0)
                {
                    return (
                        string.Empty,
                        GetFailureStatus(error));
                }
            }

            IntPtr buffer =
                Marshal.AllocHGlobal(
                    (int)requiredSize);

            try
            {
                if (!GetTokenInformation(
                        tokenHandle,
                        TokenInformationClass.TokenUser,
                        buffer,
                        requiredSize,
                        out _))
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    return (
                        string.Empty,
                        GetFailureStatus(error));
                }

                TOKEN_USER tokenUser =
                    Marshal.PtrToStructure<TOKEN_USER>(
                        buffer);

                if (tokenUser.User.Sid == IntPtr.Zero)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                uint nameLength = 0;
                uint domainLength = 0;

                bool firstLookupSucceeded =
                    LookupAccountSidW(
                        null,
                        tokenUser.User.Sid,
                        new StringBuilder(),
                        ref nameLength,
                        new StringBuilder(),
                        ref domainLength,
                        out _);

                int lookupError =
                    Marshal.GetLastWin32Error();

                if (firstLookupSucceeded)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                if (lookupError != ERROR_INSUFFICIENT_BUFFER ||
                    nameLength == 0)
                {
                    return (
                        string.Empty,
                        GetFailureStatus(lookupError));
                }

                StringBuilder name =
                    new StringBuilder(
                        (int)nameLength);

                StringBuilder domain =
                    new StringBuilder(
                        (int)Math.Max(domainLength, 1));

                if (!LookupAccountSidW(
                        null,
                        tokenUser.User.Sid,
                        name,
                        ref nameLength,
                        domain,
                        ref domainLength,
                        out _))
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    return (
                        string.Empty,
                        GetFailureStatus(error));
                }

                if (domain.Length == 0)
                {
                    return (
                        name.ToString(),
                        ProcessFieldStatus.Success);
                }

                return (
                    $"{domain}\\{name}",
                    ProcessFieldStatus.Success);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // === 4.5 修改：ReadIntegrityLevel 返回元组 ===
        private static (
            string Value,
            ProcessFieldStatus Status)
            ReadIntegrityLevel(
                IntPtr tokenHandle)
        {
            if (!GetTokenInformation(
                    tokenHandle,
                    TokenInformationClass.TokenIntegrityLevel,
                    IntPtr.Zero,
                    0,
                    out uint requiredSize))
            {
                int error =
                    Marshal.GetLastWin32Error();

                if (error != ERROR_INSUFFICIENT_BUFFER ||
                    requiredSize == 0)
                {
                    return (
                        string.Empty,
                        GetFailureStatus(error));
                }
            }

            IntPtr buffer =
                Marshal.AllocHGlobal(
                    (int)requiredSize);

            try
            {
                if (!GetTokenInformation(
                        tokenHandle,
                        TokenInformationClass.TokenIntegrityLevel,
                        buffer,
                        requiredSize,
                        out _))
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    return (
                        string.Empty,
                        GetFailureStatus(error));
                }

                TOKEN_MANDATORY_LABEL label =
                    Marshal.PtrToStructure<
                        TOKEN_MANDATORY_LABEL>(
                            buffer);

                if (label.Label.Sid == IntPtr.Zero)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                IntPtr countPointer =
                    GetSidSubAuthorityCount(
                        label.Label.Sid);

                if (countPointer == IntPtr.Zero)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                byte count =
                    Marshal.ReadByte(countPointer);

                if (count == 0)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                IntPtr authorityPointer =
                    GetSidSubAuthority(
                        label.Label.Sid,
                        (uint)(count - 1));

                if (authorityPointer == IntPtr.Zero)
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                uint rid =
                    unchecked(
                        (uint)Marshal.ReadInt32(
                            authorityPointer));

                string result =
                    rid switch
                    {
                        _ when rid >=
                            SECURITY_MANDATORY_SYSTEM_RID
                            => "SYSTEM",

                        _ when rid >=
                            SECURITY_MANDATORY_HIGH_RID
                            => "HIGH",

                        _ when rid >=
                            SECURITY_MANDATORY_MEDIUM_RID
                            => "MEDIUM",

                        _ when rid >=
                            SECURITY_MANDATORY_LOW_RID
                            => "LOW",

                        _ when rid >=
                            SECURITY_MANDATORY_UNTRUSTED_RID
                            => "UNTRUSTED",

                        _ => string.Empty
                    };

                if (string.IsNullOrEmpty(result))
                {
                    return (
                        string.Empty,
                        ProcessFieldStatus.QueryFailed);
                }

                return (
                    result,
                    ProcessFieldStatus.Success);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // === 4.6 修改：TryGetProtectionState 返回元组 ===
        private static (
            ProcessProtectionState State,
            ProcessFieldStatus Status)
            TryGetProtectionState(
                IntPtr processHandle)
        {
            if (!OperatingSystem.IsWindowsVersionAtLeast(
                    10, 0, 22000))
            {
                return (
                    ProcessProtectionState.Unknown,
                    ProcessFieldStatus.NotSupported);
            }

            PROCESS_PROTECTION_LEVEL_INFORMATION
                information =
                    new PROCESS_PROTECTION_LEVEL_INFORMATION();

            try
            {
                bool success =
                    GetProcessInformation(
                        processHandle,
                        ProcessProtectionLevelInfo,
                        ref information,
                        (uint)Marshal.SizeOf<
                            PROCESS_PROTECTION_LEVEL_INFORMATION>());

                if (!success)
                {
                    int error =
                        Marshal.GetLastWin32Error();

                    return (
                        ProcessProtectionState.Unknown,
                        GetFailureStatus(error));
                }

                return (
                    information.ProtectionLevel ==
                        PROTECTION_LEVEL_NONE
                            ? ProcessProtectionState.Unprotected
                            : ProcessProtectionState.Protected,
                    ProcessFieldStatus.Success);
            }
            catch (EntryPointNotFoundException)
            {
                return (
                    ProcessProtectionState.Unknown,
                    ProcessFieldStatus.NotSupported);
            }
        }

        // === 4.7 新增：Win32 错误码 → ProcessFieldStatus 映射 ===
        private static ProcessFieldStatus GetFailureStatus(
            int error)
        {
            return error switch
            {
                5    // ERROR_ACCESS_DENIED
                    => ProcessFieldStatus.AccessDenied,

                1314 // ERROR_PRIVILEGE_NOT_HELD
                    => ProcessFieldStatus.AccessDenied,

                1    // ERROR_INVALID_FUNCTION
                    => ProcessFieldStatus.NotSupported,

                50   // ERROR_NOT_SUPPORTED
                    => ProcessFieldStatus.NotSupported,

                120  // ERROR_CALL_NOT_IMPLEMENTED
                    => ProcessFieldStatus.NotSupported,

                127  // ERROR_PROC_NOT_FOUND
                    => ProcessFieldStatus.NotSupported,

                _    // 其它一律归为查询失败
                    => ProcessFieldStatus.QueryFailed
            };
        }

        internal sealed class NativeProcessRecord
        {
            public uint ProcessId { get; init; }

            public uint ParentProcessId { get; init; }

            public string Name { get; init; } = string.Empty;

            public string ExecutablePath { get; init; } = string.Empty;

            public ProcessFieldStatus ExecutablePathStatus { get; init; }
                = ProcessFieldStatus.NotAvailable;

            public string UserName { get; init; } = string.Empty;

            public ProcessFieldStatus UserNameStatus { get; init; }
                = ProcessFieldStatus.NotAvailable;

            public string IntegrityLevel { get; init; } = string.Empty;

            public ProcessFieldStatus IntegrityLevelStatus { get; init; }
                = ProcessFieldStatus.NotAvailable;

            public ProcessProtectionState ProtectionState { get; init; }
                = ProcessProtectionState.Unknown;

            public ProcessFieldStatus ProtectionStateStatus { get; init; }
                = ProcessFieldStatus.NotAvailable;
        }
    }
}