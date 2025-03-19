using System;

namespace ComplianceMonitor.Domain.Entities
{
    public class Alert
    {
        public Guid Id { get; private set; }
        public ComplianceCheck ComplianceCheck { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public bool Acknowledged { get; private set; }
        public string AcknowledgedBy { get; private set; }
        public DateTime? AcknowledgedAt { get; private set; }

        private Alert() { }

        public Alert(ComplianceCheck complianceCheck)
        {
            Id = Guid.NewGuid();
            ComplianceCheck = complianceCheck ?? throw new ArgumentNullException(nameof(complianceCheck));
            CreatedAt = DateTime.UtcNow;
            Acknowledged = false;
        }

        public void Acknowledge(string user)
        {
            if (string.IsNullOrWhiteSpace(user))
                throw new ArgumentException("User cannot be empty", nameof(user));

            Acknowledged = true;
            AcknowledgedBy = user;
            AcknowledgedAt = DateTime.UtcNow;
        }
    }
}