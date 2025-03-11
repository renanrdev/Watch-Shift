using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Application.Interfaces
{
    public interface IPolicyEngine
    {
        Task<Policy> CreatePolicyAsync(string name, string description, SeverityLevel severity,
            RuleType ruleType, string ruleName, Dictionary<string, object> parameters = null,
            CancellationToken cancellationToken = default);

        Task<IEnumerable<Policy>> GetAllPoliciesAsync(CancellationToken cancellationToken = default);
        Task<Policy> GetPolicyAsync(Guid policyId, CancellationToken cancellationToken = default);
        Task<ComplianceCheck> EvaluatePolicyAsync(Policy policy, KubernetesResource resource, CancellationToken cancellationToken = default);
    }
}