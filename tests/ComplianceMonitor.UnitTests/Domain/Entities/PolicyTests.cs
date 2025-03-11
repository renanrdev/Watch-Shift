using System;
using System.Collections.Generic;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using Xunit;

namespace ComplianceMonitor.UnitTests.Domain.Entities
{
    public class PolicyTests
    {
        [Fact]
        public void Policy_Create_ShouldSetProperties()
        {
            // Arrange
            var name = "Test Policy";
            var description = "Test Description";
            var severity = SeverityLevel.High;
            var ruleType = RuleType.Rbac;
            var parameters = new Dictionary<string, object> { { "key", "value" } };

            // Act
            var policy = new Policy(name, description, severity, ruleType, parameters);

            // Assert
            Assert.Equal(name, policy.Name);
            Assert.Equal(description, policy.Description);
            Assert.Equal(severity, policy.Severity);
            Assert.Equal(ruleType, policy.RuleType);
            Assert.Equal(parameters, policy.Parameters);
            Assert.True(policy.IsEnabled);
            Assert.NotEqual(Guid.Empty, policy.Id);
        }

        [Fact]
        public void Policy_EmptyName_ShouldThrowArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                new Policy("", "Description", SeverityLevel.High, RuleType.Rbac));
        }

        [Fact]
        public void Policy_UpdateName_ShouldUpdateNameAndTimestamp()
        {
            // Arrange
            var policy = new Policy("Old Name", "Description", SeverityLevel.High, RuleType.Rbac);
            var initialTimestamp = policy.UpdatedAt;

            // Wait to ensure timestamp changes
            System.Threading.Thread.Sleep(10);

            // Act
            policy.UpdateName("New Name");

            // Assert
            Assert.Equal("New Name", policy.Name);
            Assert.NotEqual(initialTimestamp, policy.UpdatedAt);
        }

        [Fact]
        public void Policy_EnableDisable_ShouldToggleEnabledState()
        {
            // Arrange
            var policy = new Policy("Test", "Description", SeverityLevel.High, RuleType.Rbac);
            Assert.True(policy.IsEnabled);

            // Act
            policy.Disable();

            // Assert
            Assert.False(policy.IsEnabled);

            // Act
            policy.Enable();

            // Assert
            Assert.True(policy.IsEnabled);
        }
    }
}