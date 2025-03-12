using System;
using System.Collections.Generic;
using System.Linq;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Domain.Entities
{
    public class ImageScanResult
    {
        public Guid Id { get; private set; }
        public string ImageName { get; private set; }
        public List<Vulnerability> Vulnerabilities { get; private set; }
        public DateTime ScanTime { get; private set; }
        public Dictionary<string, object> Metadata { get; private set; }

        private ImageScanResult() { }

        public ImageScanResult(
         string imageName,
         List<Vulnerability> vulnerabilities,
         DateTime? scanTime = null,
         Dictionary<string, object> metadata = null)
        {
            Id = Guid.NewGuid();
            ImageName = imageName;
            ScanTime = scanTime ?? DateTime.UtcNow;
            Metadata = metadata ?? new Dictionary<string, object>();

            // Configure a relação
            Vulnerabilities = vulnerabilities ?? new List<Vulnerability>();
            foreach (var vulnerability in Vulnerabilities)
            {
                vulnerability.SetImageScanResultId(Id);
            }
        }

        public Dictionary<VulnerabilitySeverity, int> CountBySeverity()
        {
            return Vulnerabilities
                .GroupBy(v => v.Severity)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        public bool HasCriticalVulnerabilities()
        {
            return Vulnerabilities.Any(v => v.Severity == VulnerabilitySeverity.CRITICAL);
        }
    }
}