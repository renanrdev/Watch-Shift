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

namespace ComplianceMonitor.Application.Services
{
    public class DashboardService : IDashboardService
    {
        private readonly IPolicyRepository _policyRepository;
        private readonly IComplianceCheckRepository _checkRepository;
        private readonly IAlertRepository _alertRepository;
        private readonly IImageScanRepository _scanRepository;
        private readonly ILogger<DashboardService> _logger;

        public DashboardService(
            IPolicyRepository policyRepository,
            IComplianceCheckRepository checkRepository,
            IAlertRepository alertRepository,
            IImageScanRepository scanRepository,
            ILogger<DashboardService> logger)
        {
            _policyRepository = policyRepository ?? throw new ArgumentNullException(nameof(policyRepository));
            _checkRepository = checkRepository ?? throw new ArgumentNullException(nameof(checkRepository));
            _alertRepository = alertRepository ?? throw new ArgumentNullException(nameof(alertRepository));
            _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting compliance statistics");
                result.Errors.Add($"Error getting compliance statistics: {ex.Message}");
                result.PartialFailure = true;
            }

            // 2. Vulnerability Statistics
            try
            {
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
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability statistics");
                result.Errors.Add($"Error getting vulnerability statistics: {ex.Message}");
                result.PartialFailure = true;
            }

            // 3. Recent Alerts
            try
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
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting recent alerts");
                result.Errors.Add($"Error getting recent alerts: {ex.Message}");
                result.PartialFailure = true;
            }

            return result;
        }
    }
}