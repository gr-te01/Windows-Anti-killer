namespace Windows_Anti_killer.Controller
//ProcessClassification.cs
{
    public enum ProcessCategory
    {
        SystemComponent,
        Neutral,
        Suspicious,
        Unknown
    }

    public sealed class ProcessClassification
    {
        public ProcessCategory Category { get; init; }

        public string Reason { get; init; } = string.Empty;
    }
}
