using System;
using System.IO;

// ProcessClassifier.cs
namespace Windows_Anti_killer.Controller
{
    public sealed class ProcessClassifier
    {
        public ProcessClassification Classify(
            ProcessInfo process)
        {
            if (process == null)
            {
                throw new ArgumentNullException(
                    nameof(process));
            }

            // 路径查询未成功时，不允许继续进行基于路径的启发式判断。
            // Unknown means Unknown。
            if (process.ExecutablePathStatus !=
                ProcessFieldStatus.Success)
            {
                return new ProcessClassification
                {
                    Category =
                        ProcessCategory.Unknown,

                    Reason =
                        GetPathUnavailableReason(
                            process.ExecutablePathStatus)
                };
            }

            if (string.IsNullOrWhiteSpace(
                    process.ExecutablePath))
            {
                return new ProcessClassification
                {
                    Category =
                        ProcessCategory.Unknown,

                    Reason =
                        "进程路径为空，无法完成分类。"
                };
            }

            string normalizedPath =
                NormalizePath(
                    process.ExecutablePath);

            if (string.IsNullOrWhiteSpace(
                    normalizedPath))
            {
                return new ProcessClassification
                {
                    Category =
                        ProcessCategory.Unknown,

                    Reason =
                        "进程路径信息无效，无法完成分类。"
                };
            }

            if (IsWindowsSystemPath(
                    normalizedPath))
            {
                return new ProcessClassification
                {
                    Category =
                        ProcessCategory.SystemComponent,

                    Reason =
                        "进程位于 Windows 核心系统目录。"
                };
            }

            if (IsSuspiciousWindowsLikeProcess(
                    process))
            {
                return new ProcessClassification
                {
                    Category =
                        ProcessCategory.Suspicious,

                    Reason =
                        "进程名称具有系统组件特征，" +
                        "但可执行文件位于 Windows 核心系统目录之外。"
                };
            }

            return new ProcessClassification
            {
                Category =
                    ProcessCategory.Neutral,

                Reason =
                    "未发现当前分类器定义的明显异常特征。"
            };
        }

        private static string GetPathUnavailableReason(
            ProcessFieldStatus status)
        {
            return status switch
            {
                ProcessFieldStatus.AccessDenied =>
                    "Windows 拒绝访问进程路径，无法完成分类。",

                ProcessFieldStatus.QueryFailed =>
                    "进程路径查询失败，无法完成分类。",

                ProcessFieldStatus.NotSupported =>
                    "当前 Windows 环境不支持进程路径查询，无法完成分类。",

                ProcessFieldStatus.NotAvailable =>
                    "进程路径信息尚未获取，无法完成分类。",

                _ =>
                    "无法获取进程可执行文件路径，无法完成分类."
            };
        }

        private static bool IsWindowsSystemPath(
            string path)
        {
            string windowsDirectory =
                Environment.GetFolderPath(
                    Environment.SpecialFolder.Windows);

            if (string.IsNullOrWhiteSpace(
                    windowsDirectory))
            {
                return false;
            }

            string normalizedWindowsDirectory =
                NormalizePath(
                    windowsDirectory);

            string system32Directory =
                NormalizePath(
                    Path.Combine(
                        normalizedWindowsDirectory,
                        "System32"));

            string sysWow64Directory =
                NormalizePath(
                    Path.Combine(
                        normalizedWindowsDirectory,
                        "SysWOW64"));

            string winSxsDirectory =
                NormalizePath(
                    Path.Combine(
                        normalizedWindowsDirectory,
                        "WinSxS"));

            return path.StartsWith(
                       system32Directory + "\\",
                       StringComparison.OrdinalIgnoreCase)
                || path.Equals(
                       system32Directory,
                       StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(
                       sysWow64Directory + "\\",
                       StringComparison.OrdinalIgnoreCase)
                || path.Equals(
                       sysWow64Directory,
                       StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(
                       winSxsDirectory + "\\",
                       StringComparison.OrdinalIgnoreCase)
                || path.Equals(
                       winSxsDirectory,
                       StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSuspiciousWindowsLikeProcess(
            ProcessInfo process)
        {
            string name =
                Path.GetFileNameWithoutExtension(
                    process.Name);

            return name.Equals(
                       "svchost",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "lsass",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "winlogon",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "csrss",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "services",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "smss",
                       StringComparison.OrdinalIgnoreCase)
                || name.Equals(
                       "wininit",
                       StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizePath(
            string path)
        {
            return path
                .Trim()
                .TrimEnd('\\');
        }
    }
}