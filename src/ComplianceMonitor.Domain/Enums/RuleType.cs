namespace ComplianceMonitor.Domain.Enums
{
    public enum RuleType
    {
        SecurityContextConstraint,
        Rbac,
        NetworkPolicy,
        PodSecurity,
        ImageScan,
        CisBenchmark
    }
}