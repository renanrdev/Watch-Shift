using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ComplianceMonitor.Domain.Entities
{
    public class ComplianceReportSummary
    {
        public string Namespace { get; set; }
        public int VulnerabilityReportCount { get; set; }
        public int ConfigAuditReportCount { get; set; }
        public int TotalImageCount { get; set; }
        public VulnerabilitySummary Vulnerabilities { get; set; }
        public ConfigAuditSummary ConfigAuditResults { get; set; }
    }
}
