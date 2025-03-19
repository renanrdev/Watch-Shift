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
                var normalizedName = NormalizeImageName(imageName);
                _logger.LogInformation($"Normalized image name: {normalizedName}");

                var allReports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                    null, // Todos namespaces
                    cancellationToken);

                // Procurar reports com base no nome da imagem
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

                var latestReport = matchingReports
                    .OrderByDescending(r => r.CreationTimestamp)
                    .First();

                // Map para o modelo de dominio
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
            if (imageName.Contains(':'))
            {
                imageName = imageName.Split(':')[0];
            }

            if (imageName.Contains('/'))
            {
                var parts = imageName.Split('/');
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