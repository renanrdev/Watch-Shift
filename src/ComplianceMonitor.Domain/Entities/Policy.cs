using System;
using System.Collections.Generic;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Domain.Entities
{
    public class Policy
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public SeverityLevel Severity { get; private set; }
        public RuleType RuleType { get; private set; }
        public Dictionary<string, object> Parameters { get; private set; }
        public bool IsEnabled { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Para EF Core
        private Policy() { }

        public Policy(string name, string description, SeverityLevel severity, RuleType ruleType, Dictionary<string, object> parameters = null)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Policy name cannot be empty", nameof(name));

            Id = Guid.NewGuid();
            Name = name;
            Description = description;
            Severity = severity;
            RuleType = ruleType;
            Parameters = parameters ?? new Dictionary<string, object>();
            IsEnabled = true;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = CreatedAt;
        }

        public void UpdateName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Policy name cannot be empty", nameof(name));

            Name = name;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateDescription(string description)
        {
            Description = description;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateSeverity(SeverityLevel severity)
        {
            Severity = severity;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateParameters(Dictionary<string, object> parameters)
        {
            Parameters = parameters ?? new Dictionary<string, object>();
            UpdatedAt = DateTime.UtcNow;
        }

        public void Enable()
        {
            IsEnabled = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Disable()
        {
            IsEnabled = false;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}