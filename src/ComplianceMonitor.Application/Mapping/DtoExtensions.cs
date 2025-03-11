using System.Collections.Generic;
using System.Linq;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Application.Mapping
{
    public static class DtoExtensions
    {
        public static ComplianceStatsDto ToComplianceStatsDto(this IEnumerable<ComplianceCheck> checks)
        {
            var stats = new ComplianceStatsDto();

            foreach (var check in checks)
            {
                switch (check.Status)
                {
                    case ComplianceStatus.Compliant:
                        stats.CompliantCount++;
                        break;
                    case ComplianceStatus.NonCompliant:
                        stats.NonCompliantCount++;
                        break;
                    case ComplianceStatus.Warning:
                        stats.WarningCount++;
                        break;
                    case ComplianceStatus.Error:
                        stats.ErrorCount++;
                        break;
                }
            }

            return stats;
        }

        public static VulnerabilityStatsDto ToVulnerabilityStatsDto(this IEnumerable<ImageScanResult> scans)
        {
            var stats = new VulnerabilityStatsDto();

            foreach (var scan in scans)
            {
                var counts = scan.CountBySeverity();

                if (counts.TryGetValue(VulnerabilitySeverity.Critical, out int critical))
                    stats.Critical += critical;

                if (counts.TryGetValue(VulnerabilitySeverity.High, out int high))
                    stats.High += high;

                if (counts.TryGetValue(VulnerabilitySeverity.Medium, out int medium))
                    stats.Medium += medium;

                if (counts.TryGetValue(VulnerabilitySeverity.Low, out int low))
                    stats.Low += low;

                if (counts.TryGetValue(VulnerabilitySeverity.Unknown, out int unknown))
                    stats.Unknown += unknown;
            }

            return stats;
        }

        public static AlertDto ToAlertDto(this Alert alert)
        {
            var check = alert.ComplianceCheck;
            var policy = check.Policy;
            var resource = check.Resource;

            return new AlertDto
            {
                Id = alert.Id,
                Severity = policy.Severity.ToString().ToLower(),
                Title = policy.Name,
                Resource = resource.Namespace != null ? $"{resource.Namespace}/{resource.Name}" : resource.Name,
                Message = check.Details.TryGetValue("message", out var message) ? message.ToString() : "Compliance check failed",
                Timestamp = alert.CreatedAt
            };
        }
    }
}