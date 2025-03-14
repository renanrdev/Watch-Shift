using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
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
            try
            {
                // Get all unique running images
                _logger.LogInformation("Retrieving all pods from the cluster");
                var pods = await _kubernetesClient.GetAllPodsAsync(cancellationToken);
                _logger.LogInformation("Retrieved {PodCount} pods from the cluster", pods.Count());

                // Extract unique images com logging melhorado
                var images = new HashSet<string>();
                int podsWithImages = 0;
                int podsWithoutImages = 0;
                int totalImageReferences = 0;

                foreach (var pod in pods)
                {
                    try
                    {
                        // Verificar diretamente os containers na estrutura raw do pod
                        var podImages = new HashSet<string>();

                        // Para pods do Kubernetes/OpenShift, a estrutura de um pod é bastante específica
                        // Verificamos vários possíveis locais para imagens de contêiner

                        // 1. Verificar containers na spec direta
                        if (pod.Spec != null)
                        {
                            // Procurar em spec.containers
                            if (pod.Spec.TryGetValue("containers", out var containersObj) &&
                                containersObj is List<object> containers)
                            {
                                foreach (var containerObj in containers)
                                {
                                    if (containerObj is Dictionary<string, object> container &&
                                        container.TryGetValue("image", out var imageObj) &&
                                        imageObj is string image && !string.IsNullOrEmpty(image))
                                    {
                                        podImages.Add(image);
                                        _logger.LogDebug($"Found image in pod {pod.Name} containers: {image}");
                                    }
                                }
                            }

                            // Procurar em spec.initContainers
                            if (pod.Spec.TryGetValue("initContainers", out var initContainersObj) &&
                                initContainersObj is List<object> initContainers)
                            {
                                foreach (var containerObj in initContainers)
                                {
                                    if (containerObj is Dictionary<string, object> container &&
                                        container.TryGetValue("image", out var imageObj) &&
                                        imageObj is string image && !string.IsNullOrEmpty(image))
                                    {
                                        podImages.Add(image);
                                        _logger.LogDebug($"Found image in pod {pod.Name} initContainers: {image}");
                                    }
                                }
                            }

                            // Procurar em spec.spec.containers
                            if (pod.Spec.TryGetValue("spec", out var specObj) &&
                                specObj is Dictionary<string, object> spec)
                            {
                                if (spec.TryGetValue("containers", out var specContainersObj) &&
                                    specContainersObj is List<object> specContainers)
                                {
                                    foreach (var containerObj in specContainers)
                                    {
                                        if (containerObj is Dictionary<string, object> container &&
                                            container.TryGetValue("image", out var imageObj) &&
                                            imageObj is string image && !string.IsNullOrEmpty(image))
                                        {
                                            podImages.Add(image);
                                            _logger.LogDebug($"Found image in pod {pod.Name} spec.containers: {image}");
                                        }
                                    }
                                }

                                // Procurar em spec.spec.initContainers
                                if (spec.TryGetValue("initContainers", out var specInitContainersObj) &&
                                    specInitContainersObj is List<object> specInitContainers)
                                {
                                    foreach (var containerObj in specInitContainers)
                                    {
                                        if (containerObj is Dictionary<string, object> container &&
                                            container.TryGetValue("image", out var imageObj) &&
                                            imageObj is string image && !string.IsNullOrEmpty(image))
                                        {
                                            podImages.Add(image);
                                            _logger.LogDebug($"Found image in pod {pod.Name} spec.initContainers: {image}");
                                        }
                                    }
                                }
                            }

                            // Procurar em spec.status.containerStatuses
                            if (pod.Spec.TryGetValue("status", out var statusObj) &&
                                statusObj is Dictionary<string, object> status)
                            {
                                if (status.TryGetValue("containerStatuses", out var containerStatusesObj) &&
                                    containerStatusesObj is List<object> containerStatuses)
                                {
                                    foreach (var statusOb in containerStatuses)
                                    {
                                        if (statusOb is Dictionary<string, object> containerStatus &&
                                            containerStatus.TryGetValue("image", out var imageObj) &&
                                            imageObj is string image && !string.IsNullOrEmpty(image))
                                        {
                                            podImages.Add(image);
                                            _logger.LogDebug($"Found image in pod {pod.Name} status.containerStatuses: {image}");
                                        }
                                    }
                                }

                                // Procurar em spec.status.initContainerStatuses
                                if (status.TryGetValue("initContainerStatuses", out var initContainerStatusesObj) &&
                                    initContainerStatusesObj is List<object> initContainerStatuses)
                                {
                                    foreach (var statusOb in initContainerStatuses)
                                    {
                                        if (statusOb is Dictionary<string, object> containerStatus &&
                                            containerStatus.TryGetValue("image", out var imageObj) &&
                                            imageObj is string image && !string.IsNullOrEmpty(image))
                                        {
                                            podImages.Add(image);
                                            _logger.LogDebug($"Found image in pod {pod.Name} status.initContainerStatuses: {image}");
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            _logger.LogWarning($"Pod {pod.Name} in namespace {pod.Namespace} has no spec data");
                        }

                        // Adicionar todas as imagens únicas do pod ao conjunto global
                        totalImageReferences += podImages.Count;
                        foreach (var image in podImages)
                        {
                            images.Add(image);
                        }

                        // Contar pods com e sem imagens
                        if (podImages.Count > 0)
                        {
                            podsWithImages++;
                            _logger.LogDebug($"Pod {pod.Name} in namespace {pod.Namespace} has {podImages.Count} images");
                        }
                        else
                        {
                            podsWithoutImages++;
                            _logger.LogWarning($"No images found in pod {pod.Name} in namespace {pod.Namespace}");

                            // Se nenhuma imagem foi encontrada, fazer log das chaves disponíveis para depuração
                            if (pod.Spec != null)
                            {
                                _logger.LogDebug($"Pod {pod.Name} spec keys: {string.Join(", ", pod.Spec.Keys)}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error extracting images from pod {pod.Name}");
                    }
                }

                _logger.LogInformation($"Pods summary: pods with images: {podsWithImages}, pods without images: {podsWithoutImages}");
                _logger.LogInformation($"Image summary: found {images.Count} unique images from {totalImageReferences} total references");

                // Tratar caso em que não há imagens
                var imageList = images.ToList();
                if (imageList.Count == 0)
                {
                    // Se estamos em ambiente de desenvolvimento e a opção está habilitada,
                    // usamos as imagens padrão configuradas
                    if (_options.AddDefaultImagesInDev)
                    {
                        _logger.LogWarning("No images found in cluster. Using default development images for testing");

                        if (_options.DefaultImages != null && _options.DefaultImages.Count > 0)
                        {
                            foreach (var defaultImage in _options.DefaultImages)
                            {
                                if (!string.IsNullOrEmpty(defaultImage))
                                {
                                    imageList.Add(defaultImage);
                                    _logger.LogInformation($"Added default development image: {defaultImage}");
                                }
                            }
                        }
                        else
                        {
                            // Se nenhuma imagem foi configurada, adicionar algumas imagens conhecidas
                            imageList.Add("nginx:latest");
                            imageList.Add("registry.access.redhat.com/ubi8/ubi-minimal:latest");
                            _logger.LogInformation("Added fallback development images: nginx:latest, ubi8/ubi-minimal:latest");
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No images found in cluster and AddDefaultImagesInDev is not enabled");
                        return new BatchScanResultDto
                        {
                            Status = "completed",
                            ScannedImages = 0,
                            VulnerabilityCounts = new Dictionary<string, int>(),
                            ImageList = new List<string>()
                        };
                    }
                }

                // Log do resultado final
                _logger.LogInformation("Found {ImageCount} unique images to scan", imageList.Count);

                // Log das primeiras 10 imagens (para depuração)
                for (int i = 0; i < Math.Min(10, imageList.Count); i++)
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

                        // Verificar primeiro se já existe um scan recente que não precisa ser forçado
                        if (!force)
                        {
                            var existingScan = await _scanRepository.GetLatestByImageNameAsync(image, cancellationToken);
                            if (existingScan != null && IsScanRecent(existingScan))
                            {
                                _logger.LogInformation($"Using existing recent scan for {image}");
                                results[image] = existingScan;
                                successfulScans++;
                                continue;
                            }
                        }

                        // Se não existir scan recente ou estiver forçando, executa novo scan
                        var scanResult = await _directScanner.ScanImageAsync(image, cancellationToken);
                        if (scanResult != null)
                        {
                            results[image] = scanResult;
                            await _scanRepository.AddAsync(scanResult, cancellationToken);
                            successfulScans++;
                            _logger.LogInformation($"Successfully scanned image: {image}");
                        }
                        else
                        {
                            failedScans++;
                            _logger.LogWarning($"Scan for image {image} returned null result");
                        }
                    }
                    catch (Exception ex)
                    {
                        failedScans++;
                        _logger.LogError(ex, "Error scanning image {Image}", image);
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
                _logger.LogError(ex, "Unhandled error in batch scan process");
                return new BatchScanResultDto
                {
                    Status = "error",
                    Error = $"Unhandled error: {ex.Message}",
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
                _logger.LogDebug($"Extracting images from pod: {pod.Name}");

                if (pod.Spec != null)
                {
                    if (pod.Spec.TryGetValue("containers", out var containersObj) &&
                        containersObj is List<object> containers)
                    {
                        foreach (var containerObj in containers)
                        {
                            if (containerObj is Dictionary<string, object> container &&
                                container.TryGetValue("image", out var imageObj) &&
                                imageObj is string image && !string.IsNullOrEmpty(image))
                            {
                                images.Add(image);
                                _logger.LogDebug($"Found image in spec.containers: {image}");
                            }
                        }
                    }

                    if (pod.Spec.TryGetValue("spec", out var specObj) &&
                        specObj is Dictionary<string, object> spec)
                    {
                        if (spec.TryGetValue("containers", out var specContainersObj) &&
                            specContainersObj is List<object> specContainers)
                        {
                            foreach (var containerObj in specContainers)
                            {
                                if (containerObj is Dictionary<string, object> container &&
                                    container.TryGetValue("image", out var imageObj) &&
                                    imageObj is string image && !string.IsNullOrEmpty(image))
                                {
                                    images.Add(image);
                                    _logger.LogDebug($"Found image in spec.spec.containers: {image}");
                                }
                            }
                        }

                        if (spec.TryGetValue("initContainers", out var initContainersObj) &&
                            initContainersObj is List<object> initContainers)
                        {
                            foreach (var containerObj in initContainers)
                            {
                                if (containerObj is Dictionary<string, object> container &&
                                    container.TryGetValue("image", out var imageObj) &&
                                    imageObj is string image && !string.IsNullOrEmpty(image))
                                {
                                    images.Add(image);
                                    _logger.LogDebug($"Found image in spec.spec.initContainers: {image}");
                                }
                            }
                        }
                    }

                    if (pod.Spec.TryGetValue("status", out var statusObj) &&
                        statusObj is Dictionary<string, object> status)
                    {
                        if (status.TryGetValue("containerStatuses", out var containerStatusesObj) &&
                            containerStatusesObj is List<object> containerStatuses)
                        {
                            foreach (var containerStatusObj in containerStatuses)
                            {
                                if (containerStatusObj is Dictionary<string, object> containerStatus &&
                                    containerStatus.TryGetValue("image", out var imageObj) &&
                                    imageObj is string image && !string.IsNullOrEmpty(image))
                                {
                                    images.Add(image);
                                    _logger.LogDebug($"Found image in status.containerStatuses: {image}");
                                }
                            }
                        }

                        if (status.TryGetValue("initContainerStatuses", out var initContainerStatusesObj) &&
                            initContainerStatusesObj is List<object> initContainerStatuses)
                        {
                            foreach (var containerStatusObj in initContainerStatuses)
                            {
                                if (containerStatusObj is Dictionary<string, object> containerStatus &&
                                    containerStatus.TryGetValue("image", out var imageObj) &&
                                    imageObj is string image && !string.IsNullOrEmpty(image))
                                {
                                    images.Add(image);
                                    _logger.LogDebug($"Found image in status.initContainerStatuses: {image}");
                                }
                            }
                        }
                    }
                }

                if (images.Count == 0)
                {
                    _logger.LogWarning($"No images found in pod {pod.Name} (namespace: {pod.Namespace})");

                    _logger.LogDebug($"Pod structure: {JsonSerializer.Serialize(pod.Spec)}");
                }
                else
                {
                    _logger.LogDebug($"Extracted {images.Count} images from pod {pod.Name}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error extracting images from pod {pod.Name}");
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

        /// <summary>
        /// Adiciona imagens padrão de teste quando nenhuma imagem é encontrada no cluster
        /// Esta opção deve ser usada apenas em ambiente de desenvolvimento
        /// </summary>
        public bool AddDefaultImagesInDev { get; set; } = false;

        /// <summary>
        /// Lista de imagens padrão para escanear quando AddDefaultImagesInDev é true
        /// </summary>
        public List<string> DefaultImages { get; set; } = new List<string>
    {
        "nginx:latest",
        "registry.access.redhat.com/ubi8/ubi-minimal:latest",
        "quay.io/centos/centos:stream8",
        "mcr.microsoft.com/dotnet/aspnet:8.0"
    };
    }

}