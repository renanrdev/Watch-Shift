using System;
using System.Collections.Generic;
using System.Linq;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;

namespace ComplianceMonitor.Domain.Specifications.Rules.RBAC
{
    public class ClusterAdminRBACRule : IPolicyRule
    {
        public ComplianceStatus Evaluate(KubernetesResource resource)
        {
            if (!AppliesTo(resource))
            {
                return ComplianceStatus.Unknown;
            }

            if (!resource.Spec.TryGetValue("roleRef", out var roleRefObj) ||
                !(roleRefObj is Dictionary<string, object> roleRef))
            {
                return ComplianceStatus.Unknown;
            }

            if (roleRef.TryGetValue("name", out var nameObj) && nameObj?.ToString() == "cluster-admin" &&
                roleRef.TryGetValue("kind", out var kindObj) && kindObj?.ToString() == "ClusterRole")
            {
                if (resource.Spec.TryGetValue("subjects", out var subjectsObj) &&
                    subjectsObj is List<object> subjects)
                {
                    foreach (var subjectObj in subjects)
                    {
                        if (subjectObj is Dictionary<string, object> subject &&
                            IsUntrustedSubject(subject))
                        {
                            return ComplianceStatus.NonCompliant;
                        }
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
                ["rule_name"] = "cluster_admin_check",
                ["description"] = "RoleBindings should not grant cluster-admin to untrusted subjects"
            };
        }

        public bool AppliesTo(KubernetesResource resource)
        {
            return resource.Kind == "ClusterRoleBinding" || resource.Kind == "RoleBinding";
        }

        private bool IsUntrustedSubject(Dictionary<string, object> subject)
        {
            var trustedServiceAccounts = new[] { "system:masters", "system:admin" };

            if (subject.TryGetValue("kind", out var kindObj) && kindObj?.ToString() == "ServiceAccount")
            {
                if (subject.TryGetValue("name", out var nameObj) &&
                    !trustedServiceAccounts.Contains(nameObj?.ToString()))
                {
                    return true;
                }
            }

            return false;
        }
    }
}