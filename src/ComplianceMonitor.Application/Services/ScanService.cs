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

namespace ComplianceMonitor.Application.Services
{
    public class ScanService : IScanService
    {
        private readonly IVulnerabilityScanner _scanner;
        private readonly IImageScanRepository _scanRepository;
        private readonly IKubernetesClient _kubernetesClient;
        private readonly IMapper _mapper;
        private readonly ILogger<ScanService> _logger;
        private readonly int _scanIntervalHours;

        public ScanService(
            IVulnerabilityScanner scanner,
            IImageScanRepository scanRepository,
            IKubernetesClient kubernetesClient,
            IMapper mapper,
            ILogger<ScanService> logger,
            int scanIntervalHours = 24)
        {
            _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
            _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
            _kubernetesClient = kubernetesClient ?? throw new ArgumentNullException(nameof(kubernetesClient));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _scanIntervalHours = scanIntervalHours;
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

            // Check if scanner is available
            bool scannerAvailable = await _scanner.IsAvailableAsync(cancellationToken);
            _logger.LogInformation("Scanner available: {ScannerAvailable}", scannerAvailable);

            // Perform the scan
            _logger.LogInformation("Starting scan of image {ImageName}", imageName);

            try
            {
                var scanResult = await _scanner.ScanImageAsync(imageName, cancellationToken);
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
                        var scanResult = await _scanner.ScanImageAsync(image, cancellationToken);
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

        public async Task<NamespaceScanSummaryDto> GetNamespaceVulnerabilitiesAsync(string @namespace, CancellationToken cancellationToken = default)
        {
            try
            {
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

                        if (severityCounts.TryGetValue(VulnerabilitySeverity.Critical, out int criticalCount))
                        {
                            criticalVulnerabilities += criticalCount;
                        }

                        if (severityCounts.TryGetValue(VulnerabilitySeverity.High, out int highCount))
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

        public async Task<ImageScanResultDto> GetImageScanAsync(string imageName, CancellationToken cancellationToken = default)
        {
            var scanResult = await _scanRepository.GetLatestByImageNameAsync(imageName, cancellationToken);
            if (scanResult == null)
            {
                throw new KeyNotFoundException($"No scan found for image: {imageName}");
            }

            return CreateImageScanResultDto(scanResult);
        }

        public async Task<Dictionary<string, object>> TestTrivyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                bool isAvailable = await _scanner.IsAvailableAsync(cancellationToken);

                if (isAvailable)
                {
                    var result = await _scanner.ScanImageAsync("nginx:latest", cancellationToken);

                    return new Dictionary<string, object>
                    {
                        ["status"] = "success",
                        ["trivy_available"] = true,
                        ["vulnerability_count"] = result.Vulnerabilities.Count,
                        ["message"] = $"Trivy is available and found {result.Vulnerabilities.Count} vulnerabilities"
                    };
                }
                else
                {
                    return new Dictionary<string, object>
                    {
                        ["status"] = "error",
                        ["trivy_available"] = false,
                        ["message"] = "Trivy is not available on any tested path"
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
            var threshold = DateTime.UtcNow.AddHours(-_scanIntervalHours);
            return scanResult.ScanTime > threshold;
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
    }
}