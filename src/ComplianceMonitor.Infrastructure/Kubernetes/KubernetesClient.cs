using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using IdentityModel.OidcClient;
using k8s;
using k8s.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Infrastructure.Kubernetes
{
    public class KubernetesClient : IKubernetesClient
    {
        private readonly k8s.Kubernetes _client;
        private readonly KubernetesClientOptions _options;
        private readonly ILogger<KubernetesClient> _logger;
        private const string TrivyGroup = "aquasecurity.github.io";
        private const string TrivyVersion = "v1alpha1";
        private const string VulnerabilityReportsPlural = "vulnerabilityreports";
        private const string ConfigAuditReportsPlural = "configauditreports";

        public KubernetesClient(IOptions<KubernetesClientOptions> options, ILogger<KubernetesClient> logger)
        {
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            try
            {
                _client = CreateClient();
                _logger.LogInformation("Kubernetes client initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing Kubernetes client");
                throw;
            }
        }

        private k8s.Kubernetes CreateClient()
        {
            KubernetesClientConfiguration config;

            if (!string.IsNullOrEmpty(_options.ApiUrl) && !string.IsNullOrEmpty(_options.Token))
            {
                // Method 1: Use API URL and token
                _logger.LogInformation("Configuring Kubernetes client with API URL and token");
                config = new KubernetesClientConfiguration
                {
                    Host = _options.ApiUrl,
                    AccessToken = _options.Token,
                    SkipTlsVerify = !_options.VerifySsl
                };
            }
            else if (File.Exists(_options.KubeconfigPath))
            {
                // Method 2: Use kubeconfig file
                _logger.LogInformation($"Configuring Kubernetes client with kubeconfig: {_options.KubeconfigPath}");
                config = KubernetesClientConfiguration.BuildConfigFromConfigFile(_options.KubeconfigPath);
            }
            else
            {
                // Method 3: Try in-cluster configuration
                _logger.LogInformation("Trying in-cluster configuration");
                config = KubernetesClientConfiguration.InClusterConfig();
            }

            return new k8s.Kubernetes(config);
        }

        public async Task<bool> CheckConnectionAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var version = await _client.CoreV1.GetAPIResourcesAsync(cancellationToken: cancellationToken);
                _logger.LogInformation("Connected to Kubernetes cluster");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check connection with Kubernetes cluster");
                return false;
            }
        }

        public async Task<IEnumerable<KubernetesResource>> GetNamespacesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var namespaces = await _client.CoreV1.ListNamespaceAsync(cancellationToken: cancellationToken);

                var result = new List<KubernetesResource>();
                foreach (var ns in namespaces.Items)
                {
                    result.Add(new KubernetesResource(
                        kind: "Namespace",
                        name: ns.Metadata.Name,
                        @namespace: null,
                        uid: ns.Metadata.Uid,
                        labels: ns.Metadata.Labels?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                        annotations: ns.Metadata.Annotations?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                        spec: new Dictionary<string, object>
                        {
                            ["status"] = new Dictionary<string, object>
                            {
                                ["phase"] = ns.Status.Phase
                            }
                        }
                    ));
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting namespaces");
                return Enumerable.Empty<KubernetesResource>();
            }
        }

        public async Task<IEnumerable<KubernetesResource>> GetSccsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var sccs = await _client.CustomObjects.ListClusterCustomObjectAsync(
                    group: "security.openshift.io",
                    version: "v1",
                    plural: "securitycontextconstraints",
                    cancellationToken: cancellationToken
                );

                var result = new List<KubernetesResource>();
                var items = ((JsonElement)sccs).GetProperty("items");

                foreach (var item in items.EnumerateArray())
                {
                    var metadata = item.GetProperty("metadata");

                    var labels = new Dictionary<string, string>();
                    if (metadata.TryGetProperty("labels", out var labelsElement))
                    {
                        foreach (var labelProp in labelsElement.EnumerateObject())
                        {
                            labels[labelProp.Name] = labelProp.Value.GetString();
                        }
                    }

                    var annotations = new Dictionary<string, string>();
                    if (metadata.TryGetProperty("annotations", out var annotationsElement))
                    {
                        foreach (var annotationProp in annotationsElement.EnumerateObject())
                        {
                            annotations[annotationProp.Name] = annotationProp.Value.GetString();
                        }
                    }

                    // Convert the JsonElement to a Dictionary<string, object>
                    var spec = JsonSerializer.Deserialize<Dictionary<string, object>>(item.ToString());

                    result.Add(new KubernetesResource(
                        kind: "SecurityContextConstraints",
                        name: metadata.GetProperty("name").GetString(),
                        @namespace: null,
                        uid: metadata.GetProperty("uid").GetString(),
                        labels: labels,
                        annotations: annotations,
                        spec: spec
                    ));
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting SCCs");
                return Enumerable.Empty<KubernetesResource>();
            }
        }

        public async Task<IEnumerable<KubernetesResource>> GetPodsAsync(string @namespace = null, CancellationToken cancellationToken = default)
        {
            try
            {
                V1PodList pods;
                if (@namespace != null)
                {
                    _logger.LogInformation($"Getting pods from namespace: {@namespace}");
                    pods = await _client.CoreV1.ListNamespacedPodAsync(namespaceParameter: @namespace, cancellationToken: cancellationToken);

                }
                else
                {
                    _logger.LogInformation("Getting pods from all namespaces");
                    pods = await _client.CoreV1.ListPodForAllNamespacesAsync(
                        cancellationToken: cancellationToken
                    );
                }

                var result = new List<KubernetesResource>();
                foreach (var pod in pods.Items)
                {
                    var spec = new Dictionary<string, object>();

                    // Add container statuses
                    var containerStatuses = new List<Dictionary<string, object>>();
                    if (pod.Status?.ContainerStatuses != null)
                    {
                        foreach (var containerStatus in pod.Status.ContainerStatuses)
                        {
                            containerStatuses.Add(new Dictionary<string, object>
                            {
                                ["name"] = containerStatus.Name,
                                ["image"] = containerStatus.Image,
                                ["imageID"] = containerStatus.ImageID,
                                ["ready"] = containerStatus.Ready,
                                ["restartCount"] = containerStatus.RestartCount,
                                ["state"] = new Dictionary<string, object>
                                {
                                    ["running"] = containerStatus.State?.Running != null
                                }
                            });
                        }
                    }

                    // Add containers from spec
                    var containers = new List<Dictionary<string, object>>();
                    if (pod.Spec?.Containers != null)
                    {
                        foreach (var container in pod.Spec.Containers)
                        {
                            containers.Add(new Dictionary<string, object>
                            {
                                ["name"] = container.Name,
                                ["image"] = container.Image
                            });
                        }
                    }

                    spec["status"] = new Dictionary<string, object>
                    {
                        ["phase"] = pod.Status?.Phase,
                        ["containerStatuses"] = containerStatuses
                    };

                    spec["spec"] = new Dictionary<string, object>
                    {
                        ["containers"] = containers,
                        ["nodeName"] = pod.Spec?.NodeName
                    };

                    result.Add(new KubernetesResource(
                        kind: "Pod",
                        name: pod.Metadata.Name,
                        @namespace: pod.Metadata.NamespaceProperty,
                        uid: pod.Metadata.Uid,
                        labels: pod.Metadata.Labels?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                        annotations: pod.Metadata.Annotations?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                        spec: spec
                    ));
                }

                _logger.LogInformation($"Found {result.Count} pods");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting pods");
                return Enumerable.Empty<KubernetesResource>();
            }
        }

        public async Task<IEnumerable<KubernetesResource>> GetAllPodsAsync(CancellationToken cancellationToken = default)
        {
            return await GetPodsAsync(null, cancellationToken);
        }

        public async Task<IEnumerable<VulnerabilityReportResource>> GetVulnerabilityReportsAsync(
             string @namespace = null,
             CancellationToken cancellationToken = default)
        {
            try
            {
                object reports;

                if (@namespace != null)
                {
                    // Get reports for a specific namespace
                    _logger.LogInformation($"Getting vulnerability reports from namespace: {@namespace}");
                    reports = await _client.CustomObjects.ListNamespacedCustomObjectAsync(
                        group: TrivyGroup,
                        version: TrivyVersion,
                        namespaceParameter: @namespace,
                        plural: VulnerabilityReportsPlural,
                        cancellationToken: cancellationToken
                    );
                }
                else
                {
                    // Get reports from all namespaces
                    _logger.LogInformation("Getting vulnerability reports from all namespaces");
                    reports = await _client.CustomObjects.ListClusterCustomObjectAsync(
                        group: TrivyGroup,
                        version: TrivyVersion,
                        plural: VulnerabilityReportsPlural,
                        cancellationToken: cancellationToken
                    );
                }

                var result = new List<VulnerabilityReportResource>();
                var items = ((JsonElement)reports).GetProperty("items");

                foreach (var item in items.EnumerateArray())
                {
                    try
                    {
                        var report = DeserializeVulnerabilityReport(item);
                        if (report != null)
                        {
                            result.Add(report);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error deserializing vulnerability report");
                    }
                }

                _logger.LogInformation($"Found {result.Count} vulnerability reports");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting vulnerability reports from Trivy Operator");
                return Enumerable.Empty<VulnerabilityReportResource>();
            }
        }

        public async Task<VulnerabilityReportResource> GetVulnerabilityReportAsync(
            string name,
            string @namespace,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation($"Getting vulnerability report {name} in namespace {@namespace}");
                var reportObj = await _client.CustomObjects.GetNamespacedCustomObjectAsync(
                    group: TrivyGroup,
                    version: TrivyVersion,
                    namespaceParameter: @namespace,
                    plural: VulnerabilityReportsPlural,
                    name: name,
                    cancellationToken: cancellationToken
                );

                var reportElement = (JsonElement)reportObj;
                return DeserializeVulnerabilityReport(reportElement);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting vulnerability report {name} in namespace {@namespace}");
                return null;
            }
        }

        public async Task<IEnumerable<ConfigAuditReportResource>> GetConfigAuditReportsAsync(
            string @namespace = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                object reports;

                if (@namespace != null)
                {
                    // Get reports for a specific namespace
                    _logger.LogInformation($"Getting config audit reports from namespace: {@namespace}");
                    reports = await _client.CustomObjects.ListNamespacedCustomObjectAsync(
                        group: TrivyGroup,
                        version: TrivyVersion,
                        namespaceParameter: @namespace,
                        plural: ConfigAuditReportsPlural,
                        cancellationToken: cancellationToken
                    );
                }
                else
                {
                    // Get reports from all namespaces
                    _logger.LogInformation("Getting config audit reports from all namespaces");
                    reports = await _client.CustomObjects.ListClusterCustomObjectAsync(
                        group: TrivyGroup,
                        version: TrivyVersion,
                        plural: ConfigAuditReportsPlural,
                        cancellationToken: cancellationToken
                    );
                }

                var result = new List<ConfigAuditReportResource>();
                var items = ((JsonElement)reports).GetProperty("items");

                foreach (var item in items.EnumerateArray())
                {
                    try
                    {
                        var report = DeserializeConfigAuditReport(item);
                        if (report != null)
                        {
                            result.Add(report);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error deserializing config audit report");
                    }
                }

                _logger.LogInformation($"Found {result.Count} config audit reports");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting config audit reports from Trivy Operator");
                return Enumerable.Empty<ConfigAuditReportResource>();
            }
        }

        private VulnerabilityReportResource DeserializeVulnerabilityReport(JsonElement reportElement)
        {
            try
            {
                // Extract metadata
                var metadata = reportElement.GetProperty("metadata");
                var name = metadata.GetProperty("name").GetString();
                var ns = metadata.GetProperty("namespace").GetString();
                var uid = metadata.GetProperty("uid").GetString();
                DateTime creationTimestamp = DateTime.UtcNow;

                if (metadata.TryGetProperty("creationTimestamp", out var creationTimestampElement))
                {
                    DateTime.TryParse(creationTimestampElement.GetString(), out creationTimestamp);
                }

                // Extract report details
                var report = reportElement.GetProperty("report");
                var artifact = report.GetProperty("artifact");
                var imageName = artifact.GetProperty("repository").GetString();
                var imageTag = artifact.TryGetProperty("tag", out var tagElement) ? tagElement.GetString() : "latest";
                var fullImageName = $"{imageName}:{imageTag}";

                // Extract vulnerabilities
                var vulnerabilities = new List<VulnerabilityItem>();
                if (report.TryGetProperty("vulnerabilities", out var vulnsElement) && vulnsElement.ValueKind != JsonValueKind.Null)
                {
                    foreach (var vulnElement in vulnsElement.EnumerateArray())
                    {
                        var vuln = new VulnerabilityItem
                        {
                            VulnerabilityID = vulnElement.GetProperty("vulnerabilityID").GetString(),
                            PkgName = vulnElement.GetProperty("pkgName").GetString(),
                            InstalledVersion = vulnElement.GetProperty("installedVersion").GetString(),
                            FixedVersion = vulnElement.TryGetProperty("fixedVersion", out var fixedElement) ?
                                fixedElement.GetString() : null,
                            Severity = ParseSeverity(vulnElement.GetProperty("severity").GetString()),
                            Description = vulnElement.TryGetProperty("description", out var descElement) ?
                                descElement.GetString() : null
                        };

                        // Extract CVSS score if available
                        if (vulnElement.TryGetProperty("cvss", out var cvssElement))
                        {
                            // Get the highest score available (v3 preferred over v2)
                            if (cvssElement.TryGetProperty("v3", out var v3Element) &&
                                v3Element.TryGetProperty("baseScore", out var baseScoreElement))
                            {
                                vuln.CvssScore = baseScoreElement.GetDouble();
                            }
                            else if (cvssElement.TryGetProperty("v2", out var v2Element) &&
                                     v2Element.TryGetProperty("baseScore", out var v2BaseScoreElement))
                            {
                                vuln.CvssScore = v2BaseScoreElement.GetDouble();
                            }
                        }

                        vulnerabilities.Add(vuln);
                    }
                }

                // Create and return the report
                return new VulnerabilityReportResource
                {
                    Name = name,
                    Namespace = ns,
                    Uid = uid,
                    CreationTimestamp = creationTimestamp,
                    ImageName = fullImageName,
                    Vulnerabilities = vulnerabilities
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing vulnerability report");
                throw;
            }
        }

        private ConfigAuditReportResource DeserializeConfigAuditReport(JsonElement reportElement)
        {
            try
            {
                // Extract metadata
                var metadata = reportElement.GetProperty("metadata");
                var name = metadata.GetProperty("name").GetString();
                var ns = metadata.GetProperty("namespace").GetString();
                var uid = metadata.GetProperty("uid").GetString();
                DateTime creationTimestamp = DateTime.UtcNow;

                if (metadata.TryGetProperty("creationTimestamp", out var creationTimestampElement))
                {
                    DateTime.TryParse(creationTimestampElement.GetString(), out creationTimestamp);
                }

                // Extract report details
                var report = reportElement.GetProperty("report");
                var summary = report.GetProperty("summary");

                int lowCount = 0, mediumCount = 0, highCount = 0, criticalCount = 0;

                if (summary.TryGetProperty("lowCount", out var lowElement))
                    lowCount = lowElement.GetInt32();
                if (summary.TryGetProperty("mediumCount", out var mediumElement))
                    mediumCount = mediumElement.GetInt32();
                if (summary.TryGetProperty("highCount", out var highElement))
                    highCount = highElement.GetInt32();
                if (summary.TryGetProperty("criticalCount", out var criticalElement))
                    criticalCount = criticalElement.GetInt32();

                // Extract check results
                var checks = new List<ConfigAuditCheck>();
                if (report.TryGetProperty("checks", out var checksElement))
                {
                    foreach (var checkElement in checksElement.EnumerateArray())
                    {
                        var check = new ConfigAuditCheck
                        {
                            ID = checkElement.GetProperty("checkID").GetString(),
                            Title = checkElement.GetProperty("title").GetString(),
                            Severity = ParseSeverity(checkElement.GetProperty("severity").GetString()),
                            Category = checkElement.TryGetProperty("category", out var catElement) ?
                                catElement.GetString() : null,
                            Description = checkElement.TryGetProperty("description", out var descElement) ?
                                descElement.GetString() : null,
                            Success = checkElement.GetProperty("success").GetBoolean()
                        };

                        checks.Add(check);
                    }
                }

                // Create and return the report
                return new ConfigAuditReportResource
                {
                    Name = name,
                    Namespace = ns,
                    Uid = uid,
                    CreationTimestamp = creationTimestamp,
                    LowCount = lowCount,
                    MediumCount = mediumCount,
                    HighCount = highCount,
                    CriticalCount = criticalCount,
                    Checks = checks
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing config audit report");
                throw;
            }
        }

        private VulnerabilitySeverity ParseSeverity(string severityStr)
        {
            if (Enum.TryParse<VulnerabilitySeverity>(severityStr, true, out var severity))
            {
                return severity;
            }
            return VulnerabilitySeverity.Unknown;
        }
    }

}

    public class KubernetesClientOptions
    {
        public string ApiUrl { get; set; }
        public string Token { get; set; }
        public string KubeconfigPath { get; set; } = "~/.kube/config";
        public bool VerifySsl { get; set; } = true;
    }
