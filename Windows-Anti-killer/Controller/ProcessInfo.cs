// ProcessInfo.cs
namespace Windows_Anti_killer.Controller
{
    public enum ProcessProtectionState
    {
        Unknown,
        Unprotected,
        Protected
    }

    public sealed class ProcessInfo
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