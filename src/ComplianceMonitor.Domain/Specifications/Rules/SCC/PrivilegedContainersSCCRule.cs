using System;
using System.Collections.Generic;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;

namespace ComplianceMonitor.Domain.Specifications.Rules.SCC
{
    public class PrivilegedContainersSCCRule : IPolicyRule
    {
        public ComplianceStatus Evaluate(KubernetesResource resource)
        {
            if (!AppliesTo(resource))
            {
                return ComplianceStatus.Unknown;
            }

            if (resource.Spec.TryGetValue("allowPrivilegedContainer", out var allowPrivilegedObj) &&
                allowPrivilegedObj is bool allowPrivileged && allowPrivileged)
            {
                return ComplianceStatus.NonCompliant;
            }

            return ComplianceStatus.Compliant;
        }

        public Dictionary<string, object> GetDetails()
        {
            return new Dictionary<string, object>
            {
                ["rule_type"] = "scc",
                ["rule_name"] = "privileged_containers",
                ["description"] = "SCCs should not allow privileged containers"
            };
        }

        public bool AppliesTo(KubernetesResource resource)
        {
            return resource.Kind == "SecurityContextConstraints";
        }
    }
}