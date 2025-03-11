using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Application.DTOs
{
    public class PolicyDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public SeverityLevel Severity { get; set; }
        public RuleType RuleType { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        public bool Enabled { get; set; }
    }

    public class PolicyCreateDto
    {
        [Required]
        public string Name { get; set; }

        [Required]
        public string Description { get; set; }

        [Required]
        public SeverityLevel Severity { get; set; }

        [Required]
        public RuleType RuleType { get; set; }

        [Required]
        public string RuleName { get; set; }

        public Dictionary<string, object> Parameters { get; set; }
    }

    public class PolicyUpdateDto
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public SeverityLevel? Severity { get; set; }
        public Dictionary<string, object> Parameters { get; set; }
        public bool? Enabled { get; set; }
    }
}