using System;
using System.Collections.Generic;
using System.Linq;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;

namespace ComplianceMonitor.Domain.Specifications.Rules.RBAC
{
    public class WildcardPermissionsRBACRule : IPolicyRule
    {
        public ComplianceStatus Evaluate(KubernetesResource resource)
        {
            if (!AppliesTo(resource))
            {
                return ComplianceStatus.Unknown;
            }

            if (!resource.Spec.TryGetValue("rules", out var rulesObj) ||
                !(rulesObj is List<object> rules))
            {
                return ComplianceStatus.Unknown;
            }

            foreach (var ruleObj in rules)
            {
                if (!(ruleObj is Dictionary<string, object> rule))
                {
                    continue;
                }

                // Check for wildcard resource permissions
                if (rule.TryGetValue("resources", out var resourcesObj) &&
                    resourcesObj is List<object> resources &&
                    resources.Any(r => r?.ToString() == "*"))
                {
                    // Check if verbs are also wildcard
                    if (rule.TryGetValue("verbs", out var verbsObj) &&
                        verbsObj is List<object> verbs &&
                        verbs.Any(v => v?.ToString() == "*"))
                    {
                        return ComplianceStatus.NonCompliant;
                    }
                }

                // Check for wildcard API groups
                if (rule.TryGetValue("apiGroups", out var apiGroupsObj) &&
                    apiGroupsObj is List<object> apiGroups &&
                    apiGroups.Any(g => g?.ToString() == "*"))
                {
                    // Check if resources and verbs are also wildcard
                    if (rule.TryGetValue("resources", out var resourcesObj2) &&
                        resourcesObj2 is List<object> resources2 &&
                        resources2.Any(r => r?.ToString() == "*") &&
                        rule.TryGetValue("verbs", out var verbsObj2) &&
                        verbsObj2 is List<object> verbs2 &&
                        verbs2.Any(v => v?.ToString() == "*"))
                    {
                        return ComplianceStatus.NonCompliant;
                    }
                }
            }

            return ComplianceStatus.Compliant;
        }

        public Dictionary<string, object> GetDetails()
        {
            return new Dictionary<string, object>
            {
                ["rule_type"] = "rbac",
                ["rule_name"] = "wildcard_permissions",
                ["description"] = "Roles should avoid wildcard permissions for both resources and verbs"
            };
        }

        public bool AppliesTo(KubernetesResource resource)
        {
            return resource.Kind == "ClusterRole" || resource.Kind == "Role";
        }
    }
}