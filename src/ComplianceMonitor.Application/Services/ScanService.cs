using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using ComplianceMonitor.Domain.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Application.Services
{
    public class ScanService : IScanService
    {
        private readonly IVulnerabilityScanner _directScanner;
        private readonly IVulnerabilityScanner _operatorScanner;
        private readonly IImageScanRepository _scanRepository;
        private readonly IKubernetesClient _kubernetesClient;
        private readonly IMapper _mapper;
        private readonly ILogger<ScanService> _logger;
        private readonly ScanServiceOptions _options;

        public ScanService(
            IEnumerable<IVulnerabilityScanner> scanners,
            IImageScanRepository scanRepository,
            IKubernetesClient kubernetesClient,
            IMapper mapper,
            ILogger<ScanService> logger,
            IOptions<ScanServiceOptions> options)
        {
            _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
            _kubernetesClient = kubernetesClient ?? throw new ArgumentNullException(nameof(kubernetesClient));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options?.Value ?? new ScanServiceOptions();

            // Get the scanners by their type
            var scannerList = scanners?.ToList() ?? new List<IVulnerabilityScanner>();
            _directScanner = scannerList.FirstOrDefault(s => s.GetType().Name == "TrivyScanner");
            _operatorScanner = scannerList.FirstOrDefault(s => s.GetType().Name == "TrivyOperatorScanner");

            if (_directScanner == null && _operatorScanner == null)
            {
                throw new InvalidOperationException("No vulnerability scanner available");
            }
        }

        public async Task<ImageScanResultDto> ScanImageAsync(string imageName, bool force = false, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting scan for image {ImageName}, force={Force}", imageName, force);

            // Check if there is a recent scan
            if (!force)
            {
                var latestScan = await _scanRepository.GetLatestByImageNameAsync(imageName, cancellationToken);
                if (latestScan != null && IsScanRecent(latestScan))
                {
                    _logger.LogInformation("Using recent scan result for {ImageName}", imageName);
                    return CreateImageScanResultDto(latestScan);
                }
            }

            // Determine which scanner to use
            IVulnerabilityScanner selectedScanner = null;

            // First try the Trivy Operator scanner if enabled
            if (_options.UseOperatorScanner && _operatorScanner != null)
            {
                bool operatorAvailable = await _operatorScanner.IsAvailableAsync(cancellationToken);
                if (operatorAvailable)
                {
                    _logger.LogInformation("Using Trivy Operator scanner");
                    selectedScanner = _operatorScanner;
                }
                else
                {
                    _logger.LogWarning("Trivy Operator not available");
                }
            }

            // Fall back to direct scanner if needed
            if (selectedScanner == null && _directScanner != null)
            {
                bool directAvailable = await _directScanner.IsAvailableAsync(cancellationToken);
                if (directAvailable)
                {
                    _logger.LogInformation("Using direct Trivy scanner");
                    selectedScanner = _directScanner;
                }
                else
                {
                    _logger.LogWarning("Direct Trivy scanner not available");
                }
            }

            if (selectedScanner == null)
            {
                throw new InvalidOperationException("No vulnerability scanner available");
            }

            // Perform the scan
            _logger.LogInformation("Starting scan of image {ImageName}", imageName);

            try
            {
                var scanResult = await selectedScanner.ScanImageAsync(imageName, cancellationToken);
                _logger.LogInformation("Scan completed for {ImageName}: found {VulnerabilityCount} vulnerabilities",
                    imageName, scanResult.Vulnerabilities.Count);

                // Save the result
                try
                {
                    await _scanRepository.AddAsync(scanResult, cancellationToken);
                    _logger.LogInformation("Scan result saved successfully for {ImageName}", imageName);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error saving scan result to database for {ImageName}", imageName);
                    throw;
                }

                return CreateImageScanResultDto(scanResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during image scan for {ImageName}", imageName);
                throw;
            }
        }

        public async Task<BatchScanResultDto> ScanAllImagesAsync(bool force = false, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting scan of all running images");

            try
            {
                // If Trivy Operator is available, we can get results directly from it
                if (_options.UseOperatorScanner && _operatorScanner != null &&
                    await _operatorScanner.IsAvailableAsync(cancellationToken))
                {
                    _logger.LogInformation("Using Trivy Operator for batch scan");
                    return await ScanAllImagesViaOperatorAsync(force, cancellationToken);
                }

                // Fall back to direct scanning
                _logger.LogInformation("Using direct scanner for batch scan");
                return await ScanAllImagesViaDirectScanAsync(force, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning all images");
                return new BatchScanResultDto
                {
                    Status = "error",
                    Error = ex.Message,
                    ScannedImages = 0,
                    VulnerabilityCounts = new Dictionary<string, int>(),
                    ImageList = new List<string>()
                };
            }
        }

        private async Task<BatchScanResultDto> ScanAllImagesViaOperatorAsync(bool force, CancellationToken cancellationToken)
        {
            try
            {
                // Get vulnerability reports from Trivy Operator
                var reports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                    null, // All namespaces
                    cancellationToken);

                if (!reports.Any())
                {
                    _logger.LogWarning("No vulnerability reports found from Trivy Operator");
                    return new BatchScanResultDto
                    {
                        Status = "completed",
                        ScannedImages = 0,
                        VulnerabilityCounts = new Dictionary<string, int>(),
                        ImageList = new List<string>()
                    };
                }

                // Count vulnerabilities by severity
                var vulnerabilityCounts = new Dictionary<string, int>();
                var processedImages = new HashSet<string>();

                foreach (var report in reports)
                {
                    if (!processedImages.Contains(report.ImageName))
                    {
                        processedImages.Add(report.ImageName);

                        // Convert report to ImageScanResult and save to repository
                        if (force || !await HasRecentScanAsync(report.ImageName, cancellationToken))
                        {
                            // Create vulnerabilities
                            var vulnerabilities = report.Vulnerabilities
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

                            // Create metadata
                            var metadata = new Dictionary<string, object>
                            {
                                ["reportName"] = report.Name,
                                ["reportNamespace"] = report.Namespace,
                                ["reportUid"] = report.Uid,
                                ["reportCreationTime"] = report.CreationTimestamp,
                                ["source"] = "TrivyOperator"
                            };

                            // Create and save scan result
                            var scanResult = new ImageScanResult(
                                report.ImageName,
                                vulnerabilities,
                                report.CreationTimestamp,
                                metadata
                            );

                            await _scanRepository.AddAsync(scanResult, cancellationToken);
                        }

                        // Count vulnerabilities by severity
                        foreach (var vuln in report.Vulnerabilities)
                        {
                            var severityKey = vuln.Severity.ToString();
                            if (!vulnerabilityCounts.ContainsKey(severityKey))
                            {
                                vulnerabilityCounts[severityKey] = 0;
                            }
                            vulnerabilityCounts[severityKey]++;
                        }
                    }
                }

                return new BatchScanResultDto
                {
                    Status = "completed",
                    ScannedImages = processedImages.Count,
                    VulnerabilityCounts = vulnerabilityCounts,
                    ImageList = processedImages.ToList()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability reports from Trivy Operator");
                throw;
            }
        }

        private async Task<BatchScanResultDto> ScanAllImagesViaDirectScanAsync(bool force, CancellationToken cancellationToken)
        {
            // Get all unique running images
            var pods = await _kubernetesClient.GetAllPodsAsync(cancellationToken);
            _logger.LogInformation("Retrieved {PodCount} pods from the cluster", pods.Count());

            // Extract unique images
            var images = new HashSet<string>();
            foreach (var pod in pods)
            {
                var podImages = ExtractImagesFromPod(pod);
                foreach (var image in podImages)
                {
                    images.Add(image);
                }
            }

            var imageList = images.ToList();
            _logger.LogInformation("Found {ImageCount} unique running images", imageList.Count);

            if (!imageList.Any())
            {
                _logger.LogWarning("No images found to scan");
                return new BatchScanResultDto
                {
                    Status = "completed",
                    ScannedImages = 0,
                    VulnerabilityCounts = new Dictionary<string, int>(),
                    ImageList = new List<string>()
                };
            }

            // Log the first 5 images (for debugging)
            for (int i = 0; i < Math.Min(5, imageList.Count); i++)
            {
                _logger.LogInformation("Image {Index}: {Image}", i + 1, imageList[i]);
            }

            // Scan each image
            var results = new Dictionary<string, ImageScanResult>();
            int successfulScans = 0;
            int failedScans = 0;

            foreach (var image in imageList)
            {
                try
                {
                    _logger.LogInformation("Scanning image: {Image}", image);
                    var scanResult = await _directScanner.ScanImageAsync(image, cancellationToken);
                    if (scanResult != null)
                    {
                        results[image] = scanResult;
                        await _scanRepository.AddAsync(scanResult, cancellationToken);
                        successfulScans++;
                    }
                }
                catch (Exception ex)
                {
                    failedScans++;
                    _logger.LogError(ex, "Error scanning image {Image}", image);
                    // Continue to the next image
                }

                _logger.LogInformation("Progress: {Successful}/{Total} completed successfully, {Failed} failures",
                    successfulScans, imageList.Count, failedScans);
            }

            _logger.LogInformation("Scan completed. Total: {Total} images, Success: {Successful}, Failures: {Failed}",
                imageList.Count, successfulScans, failedScans);

            // Prepare vulnerability counts
            var vulnerabilityCounts = new Dictionary<string, int>();
            foreach (var scanResult in results.Values)
            {
                var counts = scanResult.CountBySeverity();
                foreach (var kvp in counts)
                {
                    var severityKey = kvp.Key.ToString();
                    if (!vulnerabilityCounts.ContainsKey(severityKey))
                    {
                        vulnerabilityCounts[severityKey] = 0;
                    }
                    vulnerabilityCounts[severityKey] += kvp.Value;
                }
            }

            return new BatchScanResultDto
            {
                Status = "completed",
                ScannedImages = successfulScans,
                VulnerabilityCounts = vulnerabilityCounts,
                ImageList = results.Keys.ToList()
            };
        }

        public async Task<NamespaceScanSummaryDto> GetNamespaceVulnerabilitiesAsync(string @namespace, CancellationToken cancellationToken = default)
        {
            try
            {
                // If Trivy Operator is available, get reports directly from it
                if (_options.UseOperatorScanner)
                {
                    try
                    {
                        var operatorReports = await _kubernetesClient.GetVulnerabilityReportsAsync(
                            @namespace,
                            cancellationToken);

                        if (operatorReports.Any())
                        {
                            return CreateNamespaceSummaryFromOperatorReports(@namespace, operatorReports);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error getting vulnerability reports from Trivy Operator for namespace {Namespace}", @namespace);
                        // Continue with regular approach
                    }
                }

                // Fall back to stored scan results
                var pods = await _kubernetesClient.GetPodsAsync(@namespace, cancellationToken);
                var imageResults = new Dictionary<string, List<ImageScanResult>>();

                foreach (var pod in pods)
                {
                    var images = ExtractImagesFromPod(pod);
                    foreach (var image in images)
                    {
                        var latestScan = await _scanRepository.GetLatestByImageNameAsync(image, cancellationToken);
                        if (latestScan != null)
                        {
                            if (!imageResults.ContainsKey(image))
                            {
                                imageResults[image] = new List<ImageScanResult>();
                            }
                            imageResults[image].Add(latestScan);
                        }
                    }
                }

                // Calculate statistics
                int totalVulnerabilities = 0;
                int criticalVulnerabilities = 0;
                int highVulnerabilities = 0;
                DateTime? latestScanTime = null;

                foreach (var scans in imageResults.Values)
                {
                    foreach (var scan in scans)
                    {
                        var severityCounts = scan.CountBySeverity();
                        totalVulnerabilities += severityCounts.Sum(kvp => kvp.Value);

                        if (severityCounts.TryGetValue(VulnerabilitySeverity.CRITICAL, out int criticalCount))
                        {
                            criticalVulnerabilities += criticalCount;
                        }

                        if (severityCounts.TryGetValue(VulnerabilitySeverity.HIGH, out int highCount))
                        {
                            highVulnerabilities += highCount;
                        }

                        if (latestScanTime == null || scan.ScanTime > latestScanTime)
                        {
                            latestScanTime = scan.ScanTime;
                        }
                    }
                }

                return new NamespaceScanSummaryDto
                {
                    Namespace = @namespace,
                    ImageCount = imageResults.Count,
                    TotalVulnerabilities = totalVulnerabilities,
                    CriticalVulnerabilities = criticalVulnerabilities,
                    HighVulnerabilities = highVulnerabilities,
                    ScanTime = latestScanTime ?? DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerabilities for namespace {Namespace}", @namespace);
                throw;
            }
        }

        private NamespaceScanSummaryDto CreateNamespaceSummaryFromOperatorReports(
            string @namespace,
            IEnumerable<VulnerabilityReportResource> reports)
        {
            var uniqueImages = new HashSet<string>();
            int totalVulnerabilities = 0;
            int criticalVulnerabilities = 0;
            int highVulnerabilities = 0;
            DateTime? latestScanTime = null;

            foreach (var report in reports)
            {
                uniqueImages.Add(report.ImageName);

                totalVulnerabilities += report.Vulnerabilities.Count;
                criticalVulnerabilities += report.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.CRITICAL);
                highVulnerabilities += report.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.HIGH);

                if (latestScanTime == null || report.CreationTimestamp > latestScanTime)
                {
                    latestScanTime = report.CreationTimestamp;
                }
            }

            return new NamespaceScanSummaryDto
            {
                Namespace = @namespace,
                ImageCount = uniqueImages.Count,
                TotalVulnerabilities = totalVulnerabilities,
                CriticalVulnerabilities = criticalVulnerabilities,
                HighVulnerabilities = highVulnerabilities,
                ScanTime = latestScanTime ?? DateTime.UtcNow
            };
        }

        public async Task<ImageScanResultDto> GetImageScanAsync(string imageName, CancellationToken cancellationToken = default)
        {
            // First try to get from Trivy Operator if enabled
            if (_options.UseOperatorScanner)
            {
                try
                {
                    // Normalize image name
                    var normalizedName = NormalizeImageName(imageName);

                    // Get all reports from Trivy Operator
                    var reports = await (_kubernetesClient).GetVulnerabilityReportsAsync(
                        null, // All namespaces
                        cancellationToken);

                    // Find reports that match our image
                    var matchingReports = reports
                        .Where(r => r.ImageName.Contains(normalizedName))
                        .OrderByDescending(r => r.CreationTimestamp)
                        .ToList();

                    if (matchingReports.Any())
                    {
                        var latestReport = matchingReports.First();

                        // Convert to ImageScanResult
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

                        var scanResult = new ImageScanResult(
                            imageName,
                            vulnerabilities,
                            latestReport.CreationTimestamp,
                            metadata
                        );

                        return CreateImageScanResultDto(scanResult);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error getting vulnerability report from Trivy Operator for {ImageName}", imageName);
                    // Continue with regular approach
                }
            }

            // Fall back to database lookup
            var storedScanResult = await _scanRepository.GetLatestByImageNameAsync(imageName, cancellationToken);
            if (storedScanResult == null)
            {
                throw new KeyNotFoundException($"No scan found for image: {imageName}");
            }

            return CreateImageScanResultDto(storedScanResult);
        }

        public async Task<Dictionary<string, object>> TestTrivyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Check direct scanner
                bool directAvailable = _directScanner != null &&
                                      await _directScanner.IsAvailableAsync(cancellationToken);

                // Check operator scanner
                bool operatorAvailable = _operatorScanner != null &&
                                        await _operatorScanner.IsAvailableAsync(cancellationToken);

                if (directAvailable || operatorAvailable)
                {
                    string scannerType = directAvailable ? "Direct Trivy" : "Trivy Operator";

                    // Test scan with a common image
                    var result = directAvailable
                        ? await _directScanner.ScanImageAsync("nginx:latest", cancellationToken)
                        : await _operatorScanner.ScanImageAsync("nginx", cancellationToken);

                    return new Dictionary<string, object>
                    {
                        ["status"] = "success",
                        ["trivy_available"] = true,
                        ["scanner_type"] = scannerType,
                        ["vulnerability_count"] = result.Vulnerabilities.Count,
                        ["message"] = $"{scannerType} is available and found {result.Vulnerabilities.Count} vulnerabilities"
                    };
                }
                else
                {
                    return new Dictionary<string, object>
                    {
                        ["status"] = "error",
                        ["trivy_available"] = false,
                        ["message"] = "No vulnerability scanner is available"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing Trivy");
                return new Dictionary<string, object>
                {
                    ["status"] = "error",
                    ["error"] = ex.Message,
                    ["message"] = "Error testing Trivy"
                };
            }
        }

        private ImageScanResultDto CreateImageScanResultDto(ImageScanResult scanResult)
        {
            var dto = _mapper.Map<ImageScanResultDto>(scanResult);

            // Convert the severity counts to string keys
            var severityCounts = scanResult.CountBySeverity();
            dto.SeverityCounts = severityCounts.ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value);

            return dto;
        }

        private bool IsScanRecent(ImageScanResult scanResult)
        {
            var threshold = DateTime.UtcNow.AddHours(-_options.ScanIntervalHours);
            return scanResult.ScanTime > threshold;
        }

        private async Task<bool> HasRecentScanAsync(string imageName, CancellationToken cancellationToken)
        {
            var latestScan = await _scanRepository.GetLatestByImageNameAsync(imageName, cancellationToken);
            return latestScan != null && IsScanRecent(latestScan);
        }

        private IEnumerable<string> ExtractImagesFromPod(KubernetesResource pod)
        {
            var images = new HashSet<string>();

            try
            {
                // Extract images from status (running containers)
                if (pod.Spec.TryGetValue("status", out var statusObj) && statusObj is Dictionary<string, object> status)
                {
                    if (status.TryGetValue("containerStatuses", out var containerStatusesObj) &&
                        containerStatusesObj is List<object> containerStatuses)
                    {
                        foreach (var containerStatusObj in containerStatuses)
                        {
                            if (containerStatusObj is Dictionary<string, object> containerStatus &&
                                containerStatus.TryGetValue("image", out var imageObj) &&
                                imageObj is string image)
                            {
                                images.Add(image);
                            }
                        }
                    }
                }

                // Extract images from spec (defined containers)
                if (pod.Spec.TryGetValue("spec", out var specObj) && specObj is Dictionary<string, object> spec)
                {
                    if (spec.TryGetValue("containers", out var containersObj) &&
                        containersObj is List<object> containers)
                    {
                        foreach (var containerObj in containers)
                        {
                            if (containerObj is Dictionary<string, object> container &&
                                container.TryGetValue("image", out var imageObj) &&
                                imageObj is string image)
                            {
                                images.Add(image);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting images from pod {PodName}", pod.Name);
            }

            return images;
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

    public class ScanServiceOptions
    {
        public int ScanIntervalHours { get; set; } = 24;
        public bool UseOperatorScanner { get; set; } = true;
    }
}