using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using YamlDotNet.Core.Tokens;

namespace ComplianceMonitor.Infrastructure.Scanners
{
    public class TrivyScanner : IVulnerabilityScanner
    {
        private readonly ILogger<TrivyScanner> _logger;
        private readonly TrivyScannerOptions _options;
        private readonly List<string> _altPaths;

        public TrivyScanner(IOptions<TrivyScannerOptions> options, ILogger<TrivyScanner> logger)
        {
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Try multiple paths if default doesn't work
            _altPaths = new List<string>();
            if (OperatingSystem.IsWindows())
            {
                _altPaths.AddRange(new[]
                {
                    @"C:\ProgramData\chocolatey\bin\trivy.exe",
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "trivy", "trivy.exe"),
                    Path.Combine(Directory.GetCurrentDirectory(), "trivy", "trivy.exe")
                });
            }
            else
            {
                _altPaths.AddRange(new[]
                {
                    "/usr/local/bin/trivy",
                    "/usr/bin/trivy",
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "trivy"),
                    Path.Combine(Directory.GetCurrentDirectory(), "trivy")
                });
            }

            _logger.LogInformation($"TrivyScanner initialized with path: {_options.TrivyPath}");
            _logger.LogInformation($"OS: {Environment.OSVersion}");
            _logger.LogInformation($"Current directory: {Directory.GetCurrentDirectory()}");
            _logger.LogInformation($"Alternative paths: {string.Join(", ", _altPaths)}");
        }

        public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Checking Trivy availability using path: {_options.TrivyPath}");

                var startInfo = new ProcessStartInfo
                {
                    FileName = _options.TrivyPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    _logger.LogError("Failed to start Trivy process");
                    return await CheckAlternativePathsAsync(cancellationToken);
                }

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync(cancellationToken);

                var output = await outputTask;
                var error = await errorTask;

                if (process.ExitCode == 0)
                {
                    _logger.LogInformation($"Trivy available: {output.Trim()}");
                    return true;
                }

                _logger.LogWarning($"Trivy not available with default path. Error: {error.Trim()}");
                return await CheckAlternativePathsAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking Trivy availability");
                return await CheckAlternativePathsAsync(cancellationToken);
            }
        }

        private async Task<bool> CheckAlternativePathsAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Trying alternative paths");

            foreach (var altPath in _altPaths)
            {
                if (File.Exists(altPath))
                {
                    _logger.LogInformation($"Trying alternative path: {altPath}");

                    try
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = altPath,
                            Arguments = "--version",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        using var process = Process.Start(startInfo);
                        if (process == null) continue;

                        await process.WaitForExitAsync(cancellationToken);

                        if (process.ExitCode == 0)
                        {
                            // Update to use the path that worked
                            _options.TrivyPath = altPath;
                            var output = await process.StandardOutput.ReadToEndAsync();
                            _logger.LogInformation($"Trivy available with alternative path: {output.Trim()}");
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"Error checking alternative path {altPath}");
                    }
                }
            }

            _logger.LogError("Trivy not available on any tested path");
            return false;
        }

        public async Task<ImageScanResult> ScanImageAsync(string imageName, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Starting scan for image {imageName}");

                // Check if Trivy is available
                var isAvailable = await IsAvailableAsync(cancellationToken);
                if (!isAvailable)
                {
                    _logger.LogWarning($"Trivy not available, returning empty result for {imageName}");
                    return new ImageScanResult(
                        imageName,
                        new List<Vulnerability>(),
                        DateTime.UtcNow,
                        new Dictionary<string, object> { ["error"] = "Trivy scanner not available" }
                    );
                }

                // Execute Trivy to scan the image and get JSON result
                var timeoutArg = $"{_options.TimeoutSeconds}s";

                // Construir argumentos do comando
                var arguments = new List<string> { "image", "--format", "json", "--timeout", timeoutArg };

                // Adicionar credenciais do OpenShift se necessário
                string originalImageName = imageName;
                if (_options.UseOpenShiftCredentials)
                {
                    var token = Environment.GetEnvironmentVariable("OPENSHIFT_TOKEN");
                    if (!string.IsNullOrEmpty(token))
                    {
                        _logger.LogInformation("Using OpenShift credentials for authentication");

                        // Se a imagem parecer ser do registro interno do OpenShift (sem domínio explícito)
                        if (imageName.Contains("/") && !imageName.Contains(".") &&
                            !imageName.StartsWith("docker.io/") &&
                            !imageName.StartsWith("quay.io/"))
                        {
                            // Formato: namespace/imagename:tag
                            _logger.LogInformation("Image appears to be from internal OpenShift registry");

                            // Adicionar o prefixo do registro se necessário
                            if (!string.IsNullOrEmpty(_options.OpenShiftRegistry) &&
                                !imageName.StartsWith(_options.OpenShiftRegistry))
                            {
                                imageName = $"{_options.OpenShiftRegistry}/{imageName}";
                                _logger.LogInformation($"Using full OpenShift registry path: {imageName}");
                            }

                            // Adicionar credenciais no comando
                            arguments.Add("--username");
                            arguments.Add("sa"); // ServiceAccount username, não importa para OpenShift
                            arguments.Add("--password");
                            arguments.Add(token);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("OpenShift credentials requested but OPENSHIFT_TOKEN environment variable not set");
                    }
                }

                // Adicionar nome da imagem aos argumentos
                arguments.Add(imageName);

                // Log de comando (ocultando senha)
               // _logger.LogInformation($"Running Trivy with command: {_options.TrivyPath} {string.Join(" ", arguments.Where(a => a != token))}");

                var startInfo = new ProcessStartInfo
                {
                    FileName = _options.TrivyPath,
                    Arguments = string.Join(" ", arguments),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                // Configurar variáveis de ambiente para o Trivy
                if (_options.UseOpenShiftCredentials)
                {
                    var token = Environment.GetEnvironmentVariable("OPENSHIFT_TOKEN");
                    if (!string.IsNullOrEmpty(token))
                    {
                        // Adicionar credenciais como variáveis de ambiente também (método alternativo)
                        startInfo.EnvironmentVariables["TRIVY_USERNAME"] = "sa";
                        startInfo.EnvironmentVariables["TRIVY_PASSWORD"] = token;

                        // Variáveis de ambiente que ajudam a depurar problemas de rede
                        startInfo.EnvironmentVariables["TRIVY_DEBUG"] = "true";
                        startInfo.EnvironmentVariables["TRIVY_INSECURE"] = "true"; // Ignora erros de certificado
                    }
                }

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    throw new InvalidOperationException("Failed to start Trivy process");
                }

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                // Handle timeout correctly
                using var timeoutTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(_options.TimeoutSeconds));
                using var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(timeoutTokenSource.Token, cancellationToken);

                try
                {
                    // Await process exit with timeout
                    await process.WaitForExitAsync(linkedTokenSource.Token);

                    var output = await outputTask;
                    var error = await errorTask;

                    if (process.ExitCode != 0)
                    {
                        _logger.LogError($"Error scanning image {imageName}: ExitCode={process.ExitCode}");
                        _logger.LogError($"Error output: {error}");
                        return new ImageScanResult(
                            originalImageName,
                            new List<Vulnerability>(),
                            DateTime.UtcNow,
                            new Dictionary<string, object>
                            {
                                ["error"] = error.Trim(),
                                ["exitCode"] = process.ExitCode
                            }
                        );
                    }

                    _logger.LogInformation($"Scan completed for {imageName}, processing results");

                    // Check if output is valid JSON
                    if (string.IsNullOrWhiteSpace(output))
                    {
                        _logger.LogWarning("Trivy returned empty output");
                        return new ImageScanResult(
                            originalImageName,
                            new List<Vulnerability>(),
                            DateTime.UtcNow,
                            new Dictionary<string, object> { ["error"] = "Empty scan result" }
                        );
                    }

                    JsonDocument scanResult;
                    try
                    {
                        scanResult = JsonDocument.Parse(output);
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogError(ex, $"Error parsing Trivy JSON output for {imageName}");
                        _logger.LogError($"Invalid JSON: {output}");
                        return new ImageScanResult(
                            originalImageName,
                            new List<Vulnerability>(),
                            DateTime.UtcNow,
                            new Dictionary<string, object> { ["error"] = $"Error parsing Trivy output: {ex.Message}" }
                        );
                    }

                    var parsedResult = ParseTrivyResult(originalImageName, scanResult);
                    _logger.LogInformation($"Found {parsedResult.Vulnerabilities.Count} vulnerabilities for {originalImageName}");

                    return parsedResult;
                }
                catch (OperationCanceledException)
                {
                    if (timeoutTokenSource.IsCancellationRequested)
                    {
                        // Timeout ocorreu
                        try
                        {
                            if (!process.HasExited)
                                process.Kill();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Error killing Trivy process after timeout");
                        }

                        _logger.LogError($"Timeout scanning image {imageName}");
                        return new ImageScanResult(
                            originalImageName,
                            new List<Vulnerability>(),
                            DateTime.UtcNow,
                            new Dictionary<string, object> { ["error"] = "Timeout during scan" }
                        );
                    }

                    // Cancelamento solicitado pelo chamador, propague a exceção
                    throw;
                }
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                _logger.LogError(ex, $"Error scanning image {imageName}");
                return new ImageScanResult(
                    imageName,
                    new List<Vulnerability>(),
                    DateTime.UtcNow,
                    new Dictionary<string, object> { ["error"] = ex.Message }
                );
            }
        }

        private ImageScanResult ParseTrivyResult(string imageName, JsonDocument scanResult)
        {
            var vulnerabilities = new List<Vulnerability>();
            var metadata = new Dictionary<string, object>();

            try
            {
                // Extract basic metadata
                if (scanResult.RootElement.TryGetProperty("Metadata", out var metadataElement))
                {
                    if (metadataElement.TryGetProperty("OS", out var osElement))
                    {
                        if (osElement.TryGetProperty("Family", out var familyElement))
                        {
                            metadata["os_family"] = familyElement.GetString();
                        }

                        if (osElement.TryGetProperty("Name", out var nameElement))
                        {
                            metadata["os_name"] = nameElement.GetString();
                        }
                    }
                }

                // Extract results (Trivy organizes by "Target" - different layers/packages)
                if (scanResult.RootElement.TryGetProperty("Results", out var resultsElement))
                {
                    foreach (var result in resultsElement.EnumerateArray())
                    {
                        if (result.TryGetProperty("Target", out var targetElement))
                        {
                            var target = targetElement.GetString();

                            if (result.TryGetProperty("Vulnerabilities", out var vulnListElement))
                            {
                                _logger.LogInformation($"Processing vulnerabilities for target: {target}");

                                foreach (var vuln in vulnListElement.EnumerateArray())
                                {
                                    try
                                    {
                                        if (!vuln.TryGetProperty("VulnerabilityID", out var vulnIdElement) ||
                                            !vuln.TryGetProperty("PkgName", out var pkgNameElement) ||
                                            !vuln.TryGetProperty("InstalledVersion", out var installedVersionElement) ||
                                            !vuln.TryGetProperty("Severity", out var severityElement))
                                        {
                                            _logger.LogWarning("Vulnerability missing required fields, skipping");
                                            continue;
                                        }

                                        var vulnId = vulnIdElement.GetString();
                                        if (string.IsNullOrEmpty(vulnId))
                                        {
                                            _logger.LogWarning("Vulnerability ID is null or empty, skipping");
                                            continue;
                                        }

                                        var severityStr = severityElement.GetString()?.ToUpper() ?? "UNKNOWN";
                                        VulnerabilitySeverity severity;

                                        if (!Enum.TryParse(severityStr, true, out severity))
                                        {
                                            _logger.LogWarning($"Unknown severity: {severityStr}, using Unknown");
                                            severity = VulnerabilitySeverity.Unknown;
                                        }

                                        var references = new List<string>();
                                        if (vuln.TryGetProperty("References", out var refsElement))
                                        {
                                            foreach (var refElement in refsElement.EnumerateArray())
                                            {
                                                references.Add(refElement.GetString());
                                            }
                                        }

                                        Guid id;
                                        if (!Guid.TryParse(vulnId, out id))
                                        {
                                            id = CreateDeterministicGuid(vulnId);
                                        }

                                        vulnerabilities.Add(new Vulnerability(
                                            id: id,
                                            packageName: pkgNameElement.GetString(),
                                            installedVersion: installedVersionElement.GetString(),
                                            fixedVersion: vuln.TryGetProperty("FixedVersion", out var fixedVersionElement) ?
                                              fixedVersionElement.GetString() ?? string.Empty : string.Empty,
                                            severity: severity,
                                            description: vuln.TryGetProperty("Description", out var descriptionElement) ?
                                                descriptionElement.GetString() : string.Empty,
                                            references: references,
                                            cvssScore: ExtractCvssScore(vuln)
                                        ));
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogError(ex, "Error processing vulnerability");
                                    }
                                }
                            }
                            else
                            {
                                _logger.LogInformation($"No vulnerabilities found for target: {target}");
                            }
                        }
                    }
                }

                _logger.LogInformation($"Found {vulnerabilities.Count} vulnerabilities for {imageName}");
                return new ImageScanResult(
                    imageName,
                    vulnerabilities,
                    DateTime.UtcNow,
                    metadata
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing Trivy results");
                return new ImageScanResult(
                    imageName,
                    new List<Vulnerability>(),
                    DateTime.UtcNow,
                    new Dictionary<string, object> { ["error"] = $"Error parsing Trivy results: {ex.Message}" }
                );
            }
        }

        private Guid CreateDeterministicGuid(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input cannot be null or empty", nameof(input));

            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                return new Guid(hashBytes);
            }
        }

        private double? ExtractCvssScore(JsonElement vulnData)
        {
            try
            {
                if (!vulnData.TryGetProperty("CVSS", out var cvssElement))
                {
                    return null;
                }

                var scores = new List<double>();

                foreach (var source in cvssElement.EnumerateObject())
                {
                    var sourceObj = source.Value;

                    if (sourceObj.TryGetProperty("V3Score", out var v3ScoreElement))
                    {
                        scores.Add(v3ScoreElement.GetDouble());
                    }
                    else if (sourceObj.TryGetProperty("V2Score", out var v2ScoreElement))
                    {
                        scores.Add(v2ScoreElement.GetDouble());
                    }
                }

                return scores.Count > 0 ? scores.Max() : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error extracting CVSS score");
                return null;
            }
        }
    }

    public class TrivyScannerOptions
    {
        public string TrivyPath { get; set; } = "trivy";
        public int TimeoutSeconds { get; set; } = 300;
        public string OpenShiftRegistry { get; set; }
        public bool UseOpenShiftCredentials { get; set; } = false;
    }
}