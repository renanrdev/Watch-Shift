using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ComplianceMonitor.Domain.Entities
{
    public class ConfigAuditReportResource
    {
        public string Name { get; set; }
        public string Namespace { get; set; }
        public string Uid { get; set; }
        public DateTime CreationTimestamp { get; set; }
        public int LowCount { get; set; }
        public int MediumCount { get; set; }
        public int HighCount { get; set; }
        public int CriticalCount { get; set; }
        public List<ConfigAuditCheck> Checks { get; set; } = new List<ConfigAuditCheck>();
    }
}
