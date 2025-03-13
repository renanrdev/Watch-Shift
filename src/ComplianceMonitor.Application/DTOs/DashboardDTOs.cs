using System;
using System.Collections.Generic;

namespace ComplianceMonitor.Application.DTOs
{
    public class ComplianceStatsDto
    {
        public int CompliantCount { get; set; }
        public int NonCompliantCount { get; set; }
        public int WarningCount { get; set; }
        public int ErrorCount { get; set; }
    }

    public class VulnerabilityStatsDto
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Unknown { get; set; }
    }

    public class AlertDto
    {
        public Guid Id { get; set; }
        public string Severity { get; set; }
        public string Title { get; set; }
        public string Resource { get; set; }

        public string Source { get; set; } = "Database";
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class DashboardDto
    {
        public ComplianceStatsDto ComplianceStats { get; set; }
        public VulnerabilityStatsDto VulnerabilityStats { get; set; }
        public List<AlertDto> RecentAlerts { get; set; }
        public List<string> Errors { get; set; }
        public bool PartialFailure { get; set; }
    }
}