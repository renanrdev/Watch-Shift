using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Infrastructure.Kubernetes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace ComplianceMonitor.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ComplianceReportsController : ControllerBase
    {
        private readonly IKubernetesClient _kubernetesClient;
        private readonly ILogger<ComplianceReportsController> _logger;

        public ComplianceReportsController(
            IKubernetesClient kubernetesClient,
            ILogger<ComplianceReportsController> logger)
        {
            _kubernetesClient = kubernetesClient ?? throw new ArgumentNullException(nameof(kubernetesClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        [HttpGet("vulnerability")]
        public async Task<ActionResult<IEnumerable<VulnerabilityReportResource>>> GetVulnerabilityReports(
            [FromQuery] string ns = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var reports = await ((KubernetesClient)_kubernetesClient).GetVulnerabilityReportsAsync(
                    ns,
                    cancellationToken);

                return Ok(reports);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability reports");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { error = "Failed to retrieve vulnerability reports", details = ex.Message });
            }
        }

        [HttpGet("vulnerability/{name}")]
        public async Task<ActionResult<VulnerabilityReportResource>> GetVulnerabilityReport(
            string name,
            [FromQuery] string ns = "default",
            CancellationToken cancellationToken = default)
        {
            try
            {
                var report = await ((KubernetesClient)_kubernetesClient).GetVulnerabilityReportAsync(
                    name,
                    ns,
                    cancellationToken);

                if (report == null)
                {
                    return NotFound($"Report {name} not found in namespace {ns}");
                }

                return Ok(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability report {Name} in namespace {Namespace}", name, ns);
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { error = "Failed to retrieve vulnerability report", details = ex.Message });
            }
        }

        [HttpGet("configaudit")]
        public async Task<ActionResult<IEnumerable<ConfigAuditReportResource>>> GetConfigAuditReports(
            [FromQuery] string ns = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var reports = await ((KubernetesClient)_kubernetesClient).GetConfigAuditReportsAsync(
                    ns,
                    cancellationToken);

                return Ok(reports);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting config audit reports");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { error = "Failed to retrieve config audit reports", details = ex.Message });
            }
        }

        [HttpGet("summary")]
        public async Task<ActionResult<ComplianceReportSummary>> GetComplianceSummary(
            [FromQuery] string ns = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var vulnerabilityReports = await ((KubernetesClient)_kubernetesClient).GetVulnerabilityReportsAsync(
                    ns,
                    cancellationToken);

                var configAuditReports = await ((KubernetesClient)_kubernetesClient).GetConfigAuditReportsAsync(
                    ns,
                    cancellationToken);

                var summary = new ComplianceReportSummary
                {
                    Namespace = ns ?? "all-namespaces",
                    VulnerabilityReportCount = vulnerabilityReports.Count(),
                    ConfigAuditReportCount = configAuditReports.Count(),
                    TotalImageCount = vulnerabilityReports.Select(r => r.ImageName).Distinct().Count(),
                    Vulnerabilities = new VulnerabilitySummary(),
                    ConfigAuditResults = new ConfigAuditSummary()
                };

                foreach (var report in vulnerabilityReports)
                {
                    foreach (var vuln in report.Vulnerabilities)
                    {
                        switch (vuln.Severity)
                        {
                            case Domain.Enums.VulnerabilitySeverity.CRITICAL:
                                summary.Vulnerabilities.Critical++;
                                break;
                            case Domain.Enums.VulnerabilitySeverity.HIGH:
                                summary.Vulnerabilities.High++;
                                break;
                            case Domain.Enums.VulnerabilitySeverity.MEDIUM:
                                summary.Vulnerabilities.Medium++;
                                break;
                            case Domain.Enums.VulnerabilitySeverity.LOW:
                                summary.Vulnerabilities.Low++;
                                break;
                            default:
                                summary.Vulnerabilities.Unknown++;
                                break;
                        }
                    }
                }

                foreach (var report in configAuditReports)
                {
                    summary.ConfigAuditResults.Critical += report.CriticalCount;
                    summary.ConfigAuditResults.High += report.HighCount;
                    summary.ConfigAuditResults.Medium += report.MediumCount;
                    summary.ConfigAuditResults.Low += report.LowCount;

                    foreach (var check in report.Checks)
                    {
                        if (!check.Success)
                        {
                            summary.ConfigAuditResults.FailedChecks++;
                        }
                        summary.ConfigAuditResults.TotalChecks++;
                    }
                }

                return Ok(summary);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance summary");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { error = "Failed to generate compliance summary", details = ex.Message });
            }
        }
    }
}