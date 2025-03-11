using System.Collections.Generic;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Specifications.Rules.RBAC;
using Xunit;

namespace ComplianceMonitor.UnitTests.Domain.Specifications.Rules.RBAC
{
    public class ClusterAdminRBACRuleTests
    {
        [Fact]
        public void Evaluate_WithTrustedServiceAccount_ShouldBeCompliant()
        {
            // Arrange
            var rule = new ClusterAdminRBACRule();
            var resource = CreateClusterRoleBinding("cluster-admin", new Dictionary<string, object>
            {
                ["kind"] = "ServiceAccount",
                ["name"] = "system:masters"
            });

            // Act
            var result = rule.Evaluate(resource);

            // Assert
            Assert.Equal(ComplianceStatus.Compliant, result);
        }

        [Fact]
        public void Evaluate_WithUntrustedServiceAccount_ShouldBeNonCompliant()
        {
            // Arrange
            var rule = new ClusterAdminRBACRule();
            var resource = CreateClusterRoleBinding("cluster-admin", new Dictionary<string, object>
            {
                ["kind"] = "ServiceAccount",
                ["name"] = "untrusted-account"
            });

            // Act
            var result = rule.Evaluate(resource);

            // Assert
            Assert.Equal(ComplianceStatus.NonCompliant, result);
        }

        [Fact]
        public void AppliesTo_WithRoleBinding_ShouldReturnTrue()
        {
            // Arrange
            var rule = new ClusterAdminRBACRule();
            var resource = new KubernetesResource(
                kind: "RoleBinding",
                name: "test",
                @namespace: "default",
                uid: "123",
                spec: new Dictionary<string, object>()
            );

            // Act & Assert
            Assert.True(rule.AppliesTo(resource));
        }

        [Fact]
        public void AppliesTo_WithNonRoleBinding_ShouldReturnFalse()
        {
            // Arrange
            var rule = new ClusterAdminRBACRule();
            var resource = new KubernetesResource(
                kind: "Pod",
                name: "test",
                @namespace: "default",
                uid: "123",
                spec: new Dictionary<string, object>()
            );

            // Act & Assert
            Assert.False(rule.AppliesTo(resource));
        }

        [Fact]
        public void GetDetails_ShouldReturnRuleDetails()
        {
            // Arrange
            var rule = new ClusterAdminRBACRule();

            // Act
            var details = rule.GetDetails();

            // Assert
            Assert.Equal("rbac", details["rule_type"]);
            Assert.Equal("cluster_admin_check", details["rule_name"]);
            Assert.Contains("RoleBindings", details["description"].ToString());
        }

        private KubernetesResource CreateClusterRoleBinding(string roleName, Dictionary<string, object> subject)
        {
            return new KubernetesResource(
                kind: "ClusterRoleBinding",
                name: "test-binding",
                @namespace: null,
                uid: "123",
                spec: new Dictionary<string, object>
                {
                    ["roleRef"] = new Dictionary<string, object>
                    {
                        ["apiGroup"] = "rbac.authorization.k8s.io",
                        ["kind"] = "ClusterRole",
                        ["name"] = roleName
                    },
                    ["subjects"] = new List<object>
                    {
                        subject
                    }
                }
            );
        }
    }
}