using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Domain.Entities
{
    public class ConfigAuditCheck
    {
        public string ID { get; set; }
        public string Title { get; set; }
        public VulnerabilitySeverity Severity { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
        public bool Success { get; set; }
    }
}
