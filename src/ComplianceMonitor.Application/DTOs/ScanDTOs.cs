using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Application.DTOs
{
    public class VulnerabilityDto
    {
        public string Id { get; set; }
        public string PackageName { get; set; }
        public string InstalledVersion { get; set; }
        public string FixedVersion { get; set; }
        public VulnerabilitySeverity Severity { get; set; }
        public string Description { get; set; }
        public List<string> References { get; set; }
        public double? CvssScore { get; set; }
    }

    public class ImageScanResultDto
    {
        public Guid Id { get; set; }
        public string ImageName { get; set; }
        public DateTime ScanTime { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        public List<VulnerabilityDto> Vulnerabilities { get; set; }
        public Dictionary<string, int> SeverityCounts { get; set; }
    }

    public class ScanRequestDto
    {
        [Required]
        public string ImageName { get; set; }

        public bool Force { get; set; } = false;
    }

    public class NamespaceScanSummaryDto
    {
        public string Namespace { get; set; }
        public int ImageCount { get; set; }
        public int TotalVulnerabilities { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public DateTime ScanTime { get; set; }
    }

    public class BatchScanResultDto
    {
        public string Status { get; set; }
        public int ScannedImages { get; set; }
        public Dictionary<string, int> VulnerabilityCounts { get; set; }
        public List<string> ImageList { get; set; }
        public string Error { get; set; }
    }
}