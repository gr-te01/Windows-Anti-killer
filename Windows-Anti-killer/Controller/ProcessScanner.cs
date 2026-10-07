using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows_Anti_killer.Native;

// ProcessScanner.cs
namespace Windows_Anti_killer.Controller
{
    public sealed class ProcessScanner
    {
        public Task<IReadOnlyList<ProcessInfo>> ScanAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.Run(
                () => Scan(cancellationToken),
                cancellationToken);
        }

        private static IReadOnlyList<ProcessInfo> Scan(
            CancellationToken cancellationToken)
        {
            List<ProcessEnumeration.NativeProcessRecord> records =
                ProcessEnumeration.Enumerate();

            List<ProcessInfo> results =
                new List<ProcessInfo>(records.Count);

            foreach (
                ProcessEnumeration.NativeProcessRecord record
                in records)
            {
                cancellationToken.ThrowIfCancellationRequested();

                results.Add(
                    new ProcessInfo
                    {
                        ProcessId =
                            record.ProcessId,

                        ParentProcessId =
                            record.ParentProcessId,

                        Name =
                            record.Name,

                        ExecutablePath =
                            record.ExecutablePath,

                        ExecutablePathStatus =
                            record.ExecutablePathStatus,

                        UserName =
                            record.UserName,

                        UserNameStatus =
                            record.UserNameStatus,

                        IntegrityLevel =
                            record.IntegrityLevel,

                        IntegrityLevelStatus =
                            record.IntegrityLevelStatus,

                        ProtectionState =
                            record.ProtectionState,

                        ProtectionStateStatus =
                            record.ProtectionStateStatus
                    });
            }

            return results
                .OrderBy(process => process.ProcessId)
                .ToArray();
        }
    }
}