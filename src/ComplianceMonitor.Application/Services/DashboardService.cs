using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Application.Services
{
    public class DashboardService : IDashboardService
    {
        private readonly IPolicyRepository _policyRepository;
        private readonly IComplianceCheckRepository _checkRepository;
        private readonly IAlertRepository _alertRepository;
        private readonly IImageScanRepository _scanRepository;
        private readonly IKubernetesClient _kubernetesClient;
        private readonly ILogger<DashboardService> _logger;
        private readonly DashboardServiceOptions _options;

        public DashboardService(
            IPolicyRepository policyRepository,
            IComplianceCheckRepository checkRepository,
            IAlertRepository alertRepository,
            IImageScanRepository scanRepository,
            IKubernetesClient kubernetesClient,
            ILogger<DashboardService> logger,
            IOptions<DashboardServiceOptions> options = null)
        {
            _policyRepository = policyRepository ?? throw new ArgumentNullException(nameof(policyRepository));
            _checkRepository = checkRepository ?? throw new ArgumentNullException(nameof(checkRepository));
            _alertRepository = alertRepository ?? throw new ArgumentNullException(nameof(alertRepository));
            _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
            _kubernetesClient = kubernetesClient ?? throw new ArgumentNullException(nameof(kubernetesClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options?.Value ?? new DashboardServiceOptions();
        }

        public async Task<DashboardDto> GetDashboardDataAsync(CancellationToken cancellationToken = default)
        {
            var result = new DashboardDto
            {
                ComplianceStats = new ComplianceStatsDto(),
                VulnerabilityStats = new VulnerabilityStatsDto(),
                RecentAlerts = new List<AlertDto>(),
                Errors = new List<string>(),
                PartialFailure = false
            };

            // 1. Compliance Statistics
            try
            {
                await GetComplianceStatsAsync(result, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting compliance statistics");
                result.Errors.Add($"Error getting compliance statistics: {ex.Message}");
                result.PartialFailure = true;
            }

            // 2. Vulnerability Statistics
            try
            {
                await GetVulnerabilityStatsAsync(result, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability statistics");
                result.Errors.Add($"Error getting vulnerability statistics: {ex.Message}");
                result.PartialFailure = true;
            }

            // 3. Recent Alerts
            try
            {
                await GetRecentAlertsAsync(result, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting recent alerts");
                result.Errors.Add($"Error getting recent alerts: {ex.Message}");
                result.PartialFailure = true;
            }

            return result;
        }

        private async Task GetComplianceStatsAsync(DashboardDto result, CancellationToken cancellationToken)
        {
            // First try to get config audit reports from Trivy Operator if available
            if (_options.UseTrivyOperator)
            {
                try
                {
                    var configAuditReports = await (_kubernetesClient).GetConfigAuditReportsAsync(
                        null, // All namespaces
                        cancellationToken);

                    if (configAuditReports.Any())
                    {
                        int compliantChecks = 0;
                        int nonCompliantChecks = 0;
                        int warningChecks = 0;
                        int errorChecks = 0;

                        foreach (var report in configAuditReports)
                        {
                            foreach (var check in report.Checks)
                            {
                                if (check.Success)
                                {
                                    compliantChecks++;
                                }
                                else
                                {
                                    switch (check.Severity)
                                    {
                                        case VulnerabilitySeverity.CRITICAL:
                                        case VulnerabilitySeverity.HIGH:
                                            nonCompliantChecks++;
                                            break;
                                        case VulnerabilitySeverity.MEDIUM:
                                            warningChecks++;
                                            break;
                                        default:
                                            errorChecks++;
                                            break;
                                    }
                                }
                            }
                        }

                        result.ComplianceStats.CompliantCount = compliantChecks;
                        result.ComplianceStats.NonCompliantCount = nonCompliantChecks;
                        result.ComplianceStats.WarningCount = warningChecks;
                        result.ComplianceStats.ErrorCount = errorChecks;

                        // Trivy Operator data found, so return
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error retrieving config audit reports from Trivy Operator, falling back to database");
                    // Continue to database checks
                }
            }

            // Fall back to compliance checks from the database
            var checks = await _checkRepository.GetAllAsync(limit: 1000, cancellationToken: cancellationToken);
            foreach (var check in checks)
            {
                switch (check.Status)
                {
                    case ComplianceStatus.Compliant:
                        result.ComplianceStats.CompliantCount++;
                        break;
                    case ComplianceStatus.NonCompliant:
                        result.ComplianceStats.NonCompliantCount++;
                        break;
                    case ComplianceStatus.Warning:
                        result.ComplianceStats.WarningCount++;
                        break;
                    case ComplianceStatus.Error:
                        result.ComplianceStats.ErrorCount++;
                        break;
                }
            }
        }

        private async Task GetVulnerabilityStatsAsync(DashboardDto result, CancellationToken cancellationToken)
        {
            // First try to get vulnerability reports from Trivy Operator if available
            if (_options.UseTrivyOperator)
            {
                try
                {
                    var vulnerabilityReports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                        null, // All namespaces
                        cancellationToken);

                    if (vulnerabilityReports.Any())
                    {
                        foreach (var report in vulnerabilityReports)
                        {
                            foreach (var vuln in report.Vulnerabilities)
                            {
                                switch (vuln.Severity)
                                {
                                    case VulnerabilitySeverity.CRITICAL:
                                        result.VulnerabilityStats.Critical++;
                                        break;
                                    case VulnerabilitySeverity.HIGH:
                                        result.VulnerabilityStats.High++;
                                        break;
                                    case VulnerabilitySeverity.MEDIUM:
                                        result.VulnerabilityStats.Medium++;
                                        break;
                                    case VulnerabilitySeverity.LOW:
                                        result.VulnerabilityStats.Low++;
                                        break;
                                    default:
                                        result.VulnerabilityStats.Unknown++;
                                        break;
                                }
                            }
                        }

                        // Trivy Operator data found, so return
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error retrieving vulnerability reports from Trivy Operator, falling back to database");
                    // Continue to database lookup
                }
            }

            // Fall back to scans from the database
            var scans = await _scanRepository.GetAllAsync(limit: 20, cancellationToken: cancellationToken);
            foreach (var scan in scans)
            {
                try
                {
                    var counts = scan.CountBySeverity();
                    foreach (var kvp in counts)
                    {
                        switch (kvp.Key)
                        {
                            case VulnerabilitySeverity.CRITICAL:
                                result.VulnerabilityStats.Critical += kvp.Value;
                                break;
                            case VulnerabilitySeverity.HIGH:
                                result.VulnerabilityStats.High += kvp.Value;
                                break;
                            case VulnerabilitySeverity.MEDIUM:
                                result.VulnerabilityStats.Medium += kvp.Value;
                                break;
                            case VulnerabilitySeverity.LOW:
                                result.VulnerabilityStats.Low += kvp.Value;
                                break;
                            case VulnerabilitySeverity.Unknown:
                                result.VulnerabilityStats.Unknown += kvp.Value;
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error processing scan result");
                }
            }
        }

        private async Task GetRecentAlertsAsync(DashboardDto result, CancellationToken cancellationToken)
        {
            var alerts = await _alertRepository.GetUnacknowledgedAsync(cancellationToken);
            foreach (var alert in alerts.Take(5))
            {
                try
                {
                    var check = alert.ComplianceCheck;
                    var policy = check.Policy;
                    var resource = check.Resource;
                    var details = check.Details;

                    var alertDto = new AlertDto
                    {
                        Id = alert.Id,
                        Severity = policy.Severity.ToString().ToLower(),
                        Title = policy.Name,
                        Resource = resource.Namespace != null ? $"{resource.Namespace}/{resource.Name}" : resource.Name,
                        Message = details.TryGetValue("message", out var message) ? message.ToString() : "Compliance check failed",
                        Timestamp = alert.CreatedAt
                    };

                    result.RecentAlerts.Add(alertDto);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error processing alert");
                }
            }

            // If we don't have enough alerts from the database, try to generate some from Trivy Operator reports
            if (result.RecentAlerts.Count < 5 && _options.UseTrivyOperator)
            {
                try
                {
                    // Get failed config audit checks
                    var configAuditReports = await (_kubernetesClient).GetConfigAuditReportsAsync(
                        null,
                        cancellationToken);

                    var failedChecks = configAuditReports
                        .SelectMany(r => r.Checks.Where(c => !c.Success)
                            .Select(c => new {
                                Report = r,
                                Check = c
                            }))
                        .OrderByDescending(x => (int)x.Check.Severity)
                        .Take(5 - result.RecentAlerts.Count);

                    foreach (var failedCheck in failedChecks)
                    {
                        var alertDto = new AlertDto
                        {
                            Id = Guid.NewGuid(), // Generate a new ID since this isn't a real alert
                            Severity = failedCheck.Check.Severity.ToString().ToLower(),
                            Title = failedCheck.Check.Title,
                            Resource = $"{failedCheck.Report.Namespace}/{failedCheck.Report.Name}",
                            Message = failedCheck.Check.Description ?? "Config audit check failed",
                            Timestamp = failedCheck.Report.CreationTimestamp,
                            Source = "TrivyOperator"
                        };

                        result.RecentAlerts.Add(alertDto);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error generating alerts from Trivy Operator reports");
                }
            }
        }
    }

    public class DashboardServiceOptions
    {
        public bool UseTrivyOperator { get; set; } = true;
    }
}