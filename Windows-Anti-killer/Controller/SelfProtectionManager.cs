using Windows_Anti_killer.Native;
//SelfProtectionManager.cs
namespace Windows_Anti_killer.Controller
{
    public sealed class SelfProtectionManager
    {
        public ProtectionModuleStatus Status { get; private set; } = ProtectionModuleStatus.NotReady;
        public string StatusMessage { get; private set; } = "自身保护尚未初始化。";

        public bool Initialize()
        {
            Status = ProtectionModuleStatus.NotReady;
            StatusMessage = "正在初始化自身保护……";

            bool mitigationEnabled = ProcessMitigation.EnableExtensionPointDisable();

            if (!mitigationEnabled)
            {
                Status = ProtectionModuleStatus.Warning;
                StatusMessage = "无法启用进程扩展点禁用策略，自身保护未完全就位。";
                return false;
            }

            Status = ProtectionModuleStatus.Active;
            StatusMessage = "进程扩展点禁用策略已启用，自身保护基础层已就位。";
            return true;
        }
    }
}