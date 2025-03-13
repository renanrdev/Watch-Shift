using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Infrastructure.Scanners
{
    public class TrivyOperatorScanner : IVulnerabilityScanner
    {
        private readonly IKubernetesClient _kubernetesClient;
        private readonly ILogger<TrivyOperatorScanner> _logger;
        private readonly TrivyOperatorScannerOptions _options;

        public TrivyOperatorScanner(
            IKubernetesClient kubernetesClient,
            IOptions<TrivyOperatorScannerOptions> options,
            ILogger<TrivyOperatorScanner> logger)
        {
            _kubernetesClient = kubernetesClient ?? throw new ArgumentNullException(nameof(kubernetesClient));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Checking Trivy Operator availability");

                // Attempt to get any vulnerability reports to check if Trivy Operator is working
                var reports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                    _options.TestNamespace,
                    cancellationToken);

                var isAvailable = reports.Any();
                _logger.LogInformation($"Trivy Operator available: {isAvailable}");

                return isAvailable;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking Trivy Operator availability");
                return false;
            }
        }

        public async Task<ImageScanResult> ScanImageAsync(string imageName, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation($"Getting scan results for image {imageName} from Trivy Operator");

            try
            {
                // Normalize image name - extract repository name
                var normalizedName = NormalizeImageName(imageName);
                _logger.LogInformation($"Normalized image name: {normalizedName}");

                // Since Trivy Operator generates reports based on running pods,
                // we need to find all reports that match our image
                var allReports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                    null, // All namespaces
                    cancellationToken);

                // Find reports that match our image name
                var matchingReports = allReports
                    .Where(r => r.ImageName.Contains(normalizedName))
                    .ToList();

                if (!matchingReports.Any())
                {
                    _logger.LogWarning($"No vulnerability reports found for image {imageName}");
                    return new ImageScanResult(
                        imageName,
                        new List<Vulnerability>(),
                        DateTime.UtcNow,
                        new Dictionary<string, object> { ["error"] = "No vulnerability reports found" }
                    );
                }

                _logger.LogInformation($"Found {matchingReports.Count} vulnerability reports for image {imageName}");

                // Use the most recent report
                var latestReport = matchingReports
                    .OrderByDescending(r => r.CreationTimestamp)
                    .First();

                // Map to our domain model
                var vulnerabilities = latestReport.Vulnerabilities
                    .Select(v => new Vulnerability(
                        id: Guid.NewGuid(),
                        packageName: v.PkgName,
                        installedVersion: v.InstalledVersion,
                        fixedVersion: v.FixedVersion ?? string.Empty,
                        severity: v.Severity,
                        description: v.Description ?? string.Empty,
                        references: v.References,
                        cvssScore: v.CvssScore
                    ))
                    .ToList();

                var metadata = new Dictionary<string, object>
                {
                    ["reportName"] = latestReport.Name,
                    ["reportNamespace"] = latestReport.Namespace,
                    ["reportUid"] = latestReport.Uid,
                    ["reportCreationTime"] = latestReport.CreationTimestamp,
                    ["source"] = "TrivyOperator"
                };

                return new ImageScanResult(
                    imageName,
                    vulnerabilities,
                    latestReport.CreationTimestamp,
                    metadata
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting scan results for {imageName} from Trivy Operator");
                return new ImageScanResult(
                    imageName,
                    new List<Vulnerability>(),
                    DateTime.UtcNow,
                    new Dictionary<string, object> { ["error"] = ex.Message }
                );
            }
        }

        private string NormalizeImageName(string imageName)
        {
            // Remove tag if present
            if (imageName.Contains(':'))
            {
                imageName = imageName.Split(':')[0];
            }

            // Remove registry if present
            if (imageName.Contains('/'))
            {
                var parts = imageName.Split('/');
                // If the registry part contains a dot, it's likely a domain
                if (parts[0].Contains('.') || parts[0].Contains(':'))
                {
                    imageName = string.Join('/', parts.Skip(1));
                }
            }

            return imageName;
        }
    }

    public class TrivyOperatorScannerOptions
    {
        public string TestNamespace { get; set; } = "default";
    }
}