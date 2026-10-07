namespace Windows_Anti_killer.Controller
// ProtectionState.cs
{
    public enum ProtectionModuleStatus
    {
        Active,
        NotReady,
        Disabled,
        Warning,
        Error,
        Unknown
    }

    public sealed class ProtectionState
    {
        public ProtectionModuleStatus BasicProtection { get; set; }
            = ProtectionModuleStatus.NotReady;

        public ProtectionModuleStatus SelfProtection { get; set; }
            = ProtectionModuleStatus.NotReady;

        public ProtectionModuleStatus AntiInjection { get; set; }
            = ProtectionModuleStatus.NotReady;

        public ProtectionModuleStatus Integrity { get; set; }
            = ProtectionModuleStatus.NotReady;

        public ProtectionModuleStatus OperationSecurity { get; set; }
            = ProtectionModuleStatus.NotReady;
    }
}