namespace Windows_Anti_killer.Controller
//OperationManager.cs
{
    public enum OperationType
    {
        ViewProcess,
        TerminateProcess,
        ForceTerminateProcess,
        TerminateProcessTree,
        ModifyProtection,
        ModifySystemProtection
    }

    public enum OperationAuthorization
    {
        Allowed,
        RequiresConfirmation,
        Denied
    }

    public sealed class OperationResult
    {
        public bool Success { get; init; }

        public OperationAuthorization Authorization { get; init; }

        public string Message { get; init; } = string.Empty;

        public OperationType Operation { get; init; }

        public uint? ProcessId { get; init; }
    }

    public sealed class OperationManager
    {
        public OperationResult CheckOperation(
            OperationType operation,
            ProcessInfo? target = null,
            bool userConfirmed = false)
        {
            // === 新增：非查看操作必须有目标进程 ===
            if (target == null &&
                operation != OperationType.ViewProcess)
            {
                return new OperationResult
                {
                    Success = false,
                    Authorization = OperationAuthorization.Denied,
                    Operation = operation,
                    ProcessId = null,
                    Message = "操作缺少有效目标进程。"
                };
            }

            switch (operation)
            {
                case OperationType.ViewProcess:
                    return new OperationResult
                    {
                        Success = true,
                        Authorization = OperationAuthorization.Allowed,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "允许查看进程信息。"
                    };

                case OperationType.TerminateProcess:
                    if (!userConfirmed)
                    {
                        return new OperationResult
                        {
                            Success = false,
                            Authorization = OperationAuthorization.RequiresConfirmation,
                            Operation = operation,
                            ProcessId = target?.ProcessId,
                            Message = "结束进程需要用户确认。"
                        };
                    }
                    return new OperationResult
                    {
                        Success = true,
                        Authorization = OperationAuthorization.Allowed,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "允许执行结束进程操作。"
                    };

                case OperationType.ForceTerminateProcess:
                    if (!userConfirmed)
                    {
                        return new OperationResult
                        {
                            Success = false,
                            Authorization = OperationAuthorization.RequiresConfirmation,
                            Operation = operation,
                            ProcessId = target?.ProcessId,
                            Message = "强制结束进程需要用户明确确认。"
                        };
                    }
                    return new OperationResult
                    {
                        Success = true,
                        Authorization = OperationAuthorization.Allowed,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "允许执行强制结束进程操作。"
                    };

                case OperationType.TerminateProcessTree:
                    if (!userConfirmed)
                    {
                        return new OperationResult
                        {
                            Success = false,
                            Authorization = OperationAuthorization.RequiresConfirmation,
                            Operation = operation,
                            ProcessId = target?.ProcessId,
                            Message = "结束进程树需要用户明确确认。"
                        };
                    }
                    return new OperationResult
                    {
                        Success = true,
                        Authorization = OperationAuthorization.Allowed,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "允许执行进程树操作。"
                    };

                case OperationType.ModifyProtection:
                case OperationType.ModifySystemProtection:
                    if (!userConfirmed)
                    {
                        return new OperationResult
                        {
                            Success = false,
                            Authorization = OperationAuthorization.RequiresConfirmation,
                            Operation = operation,
                            ProcessId = target?.ProcessId,
                            Message = "修改防护状态需要用户明确确认。"
                        };
                    }
                    return new OperationResult
                    {
                        Success = true,
                        Authorization = OperationAuthorization.Allowed,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "允许执行防护修改操作。"
                    };

                default:
                    return new OperationResult
                    {
                        Success = false,
                        Authorization = OperationAuthorization.Denied,
                        Operation = operation,
                        ProcessId = target?.ProcessId,
                        Message = "未知操作类型，拒绝执行。"
                    };
            }
        }
    }
}