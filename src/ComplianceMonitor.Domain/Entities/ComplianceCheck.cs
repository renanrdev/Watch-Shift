using System;
using System.Collections.Generic;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Domain.Entities
{
    public class ComplianceCheck
    {
        public Guid Id { get; private set; }
        public Policy Policy { get; private set; }
        public KubernetesResource Resource { get; private set; }
        public ComplianceStatus Status { get; private set; }
        public Dictionary<string, object> Details { get; private set; }
        public DateTime Timestamp { get; private set; }

        private ComplianceCheck() { }

        public ComplianceCheck(
            Policy policy,
            KubernetesResource resource,
            ComplianceStatus status,
            Dictionary<string, object> details = null)
        {
            Id = Guid.NewGuid();
            Policy = policy ?? throw new ArgumentNullException(nameof(policy));
            Resource = resource ?? throw new ArgumentNullException(nameof(resource));
            Status = status;
            Details = details ?? new Dictionary<string, object>();
            Timestamp = DateTime.UtcNow;
        }
    }
}