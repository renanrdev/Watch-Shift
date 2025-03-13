using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ComplianceMonitor.Domain.Entities
{
    public class ConfigAuditSummary
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int FailedChecks { get; set; }
        public int TotalChecks { get; set; }

        public int Total => Critical + High + Medium + Low;

        public double CompliancePercentage => TotalChecks > 0
            ? Math.Round(100.0 * (TotalChecks - FailedChecks) / TotalChecks, 2)
            : 0;
    }
}
