using System;
using System.Collections.Generic;
using System.Linq;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;

namespace ComplianceMonitor.Domain.Specifications.Rules.Network
{
    public class DefaultDenyNetworkPolicyRule : IPolicyRule
    {
        public ComplianceStatus Evaluate(KubernetesResource resource)
        {
            if (!AppliesTo(resource))
            {
                return ComplianceStatus.Unknown;
            }

            // Check if it's a default deny policy
            bool isPodSelectorEmpty = false;
            bool hasNoIngressRules = false;
            bool hasNoEgressRules = false;

            // Check pod selector is empty (selects all pods)
            if (resource.Spec.TryGetValue("podSelector", out var podSelectorObj) &&
                podSelectorObj is Dictionary<string, object> podSelector)
            {
                isPodSelectorEmpty = !podSelector.ContainsKey("matchLabels") &&
                                     !podSelector.ContainsKey("matchExpressions");
            }

            // Check ingress rules
            if (resource.Spec.TryGetValue("ingress", out var ingressObj))
            {
                if (ingressObj is List<object> ingress)
                {
                    hasNoIngressRules = !ingress.Any() ||
                                       (ingress.Count == 1 &&
                                        ingress[0] is Dictionary<string, object> ingressRule &&
                                        !ingressRule.Any());
                }
            }
            else
            {
                hasNoIngressRules = true;
            }

            // Check egress rules
            if (resource.Spec.TryGetValue("egress", out var egressObj))
            {
                if (egressObj is List<object> egress)
                {
                    hasNoEgressRules = !egress.Any() ||
                                      (egress.Count == 1 &&
                                       egress[0] is Dictionary<string, object> egressRule &&
                                       !egressRule.Any());
                }
            }
            else
            {
                hasNoEgressRules = true;
            }

            if (isPodSelectorEmpty && hasNoIngressRules && hasNoEgressRules)
            {
                return ComplianceStatus.Compliant;
            }

            // It's not a default deny policy
            return ComplianceStatus.Warning;
        }

        public Dictionary<string, object> GetDetails()
        {
            return new Dictionary<string, object>
            {
                ["rule_type"] = "network",
                ["rule_name"] = "default_deny",
                ["description"] = "Namespaces should have a default deny network policy"
            };
        }

        public bool AppliesTo(KubernetesResource resource)
        {
            return resource.Kind == "NetworkPolicy";
        }
    }
}