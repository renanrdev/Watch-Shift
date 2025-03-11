using System.Collections.Generic;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Domain.Interfaces.Services
{
    public interface IPolicyRule
    {
        ComplianceStatus Evaluate(KubernetesResource resource);
        Dictionary<string, object> GetDetails();
        bool AppliesTo(KubernetesResource resource);
    }
}