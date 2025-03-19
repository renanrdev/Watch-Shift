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
                _logger.LogInformation($"Configuring Kubernetes client with kubeconfig: {_options.KubeconfigPath}");
                config = KubernetesClientConfiguration.BuildConfigFromConfigFile(_options.KubeconfigPath);
            }
            else
            {
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
            try
            {
                _logger.LogInformation("Getting pods from all namespaces");
                var podList = await _client.CoreV1.ListPodForAllNamespacesAsync(
                    cancellationToken: cancellationToken
                );

                var result = new List<KubernetesResource>();
                foreach (var pod in podList.Items)
                {
                    try
                    {
                        // Debug para os primeiros 5 pods
                        if (result.Count < 5)
                        {
                            _logger.LogDebug($"Processing pod: {pod.Metadata.Name} in namespace {pod.Metadata.NamespaceProperty}");

                            if (pod.Spec?.Containers != null)
                            {
                                foreach (var container in pod.Spec.Containers)
                                {
                                    _logger.LogDebug($"Container {container.Name} has image: {container.Image}");
                                }
                            }

                            if (pod.Status?.ContainerStatuses != null)
                            {
                                foreach (var status in pod.Status.ContainerStatuses)
                                {
                                    _logger.LogDebug($"Container status for {status.Name}, image: {status.Image}");
                                }
                            }
                        }

                        // Mapear o pod para um recurso Kubernetes
                        var resource = MapPodToResource(pod);
                        result.Add(resource);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error processing pod {pod.Metadata.Name}");
                    }
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

        private KubernetesResource MapPodToResource(V1Pod pod)
        {
            var labels = pod.Metadata.Labels != null
                ? pod.Metadata.Labels.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
                : new Dictionary<string, string>();

            var annotations = pod.Metadata.Annotations != null
                ? pod.Metadata.Annotations.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
                : new Dictionary<string, string>();

            var spec = new Dictionary<string, object>();

            // 1. Adicionar diretamente os containers e initContainers para facilidade de acesso

            // Containers regulares
            var containers = new List<Dictionary<string, object>>();
            if (pod.Spec?.Containers != null)
            {
                foreach (var container in pod.Spec.Containers)
                {
                    var containerDict = new Dictionary<string, object>
                    {
                        ["name"] = container.Name,
                        ["image"] = container.Image ?? string.Empty
                    };

                    if (container.Ports != null)
                    {
                        containerDict["ports"] = container.Ports.Select(p => new { p.ContainerPort, p.Protocol }).ToList();
                    }

                    containers.Add(containerDict);
                }
            }
            spec["containers"] = containers;

            // InitContainers
            var initContainers = new List<Dictionary<string, object>>();
            if (pod.Spec?.InitContainers != null)
            {
                foreach (var container in pod.Spec.InitContainers)
                {
                    initContainers.Add(new Dictionary<string, object>
                    {
                        ["name"] = container.Name,
                        ["image"] = container.Image ?? string.Empty
                    });
                }
            }
            spec["initContainers"] = initContainers;

            // 2. Adicionar spec como um subobject para preservar a estrutura original
            spec["spec"] = new Dictionary<string, object>
            {
                ["containers"] = containers,
                ["initContainers"] = initContainers,
                ["nodeName"] = pod.Spec?.NodeName
            };

            // 3. Adicionar status
            var status = new Dictionary<string, object>
            {
                ["phase"] = pod.Status?.Phase
            };

            var containerStatuses = new List<Dictionary<string, object>>();
            if (pod.Status?.ContainerStatuses != null)
            {
                foreach (var containerStatus in pod.Status.ContainerStatuses)
                {
                    containerStatuses.Add(new Dictionary<string, object>
                    {
                        ["name"] = containerStatus.Name,
                        ["image"] = containerStatus.Image ?? string.Empty,
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
            status["containerStatuses"] = containerStatuses;

            var initContainerStatuses = new List<Dictionary<string, object>>();
            if (pod.Status?.InitContainerStatuses != null)
            {
                foreach (var containerStatus in pod.Status.InitContainerStatuses)
                {
                    initContainerStatuses.Add(new Dictionary<string, object>
                    {
                        ["name"] = containerStatus.Name,
                        ["image"] = containerStatus.Image ?? string.Empty,
                        ["imageID"] = containerStatus.ImageID,
                        ["ready"] = containerStatus.Ready,
                        ["restartCount"] = containerStatus.RestartCount
                    });
                }
            }
            status["initContainerStatuses"] = initContainerStatuses;

            spec["status"] = status;

            // Criar e retornar o KubernetesResource
            return new KubernetesResource(
                kind: "Pod",
                name: pod.Metadata.Name,
                @namespace: pod.Metadata.NamespaceProperty,
                uid: pod.Metadata.Uid,
                labels: labels,
                annotations: annotations,
                spec: spec
            );
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
                if (!reportElement.TryGetProperty("metadata", out var metadata))
                {
                    _logger.LogWarning("Report doesn't contain metadata property");
                    return null;
                }

                if (!metadata.TryGetProperty("name", out var nameElement))
                {
                    _logger.LogWarning("Metadata doesn't contain name property");
                    return null;
                }
                var name = nameElement.GetString();

                if (!metadata.TryGetProperty("namespace", out var namespaceElement))
                {
                    _logger.LogWarning("Metadata doesn't contain namespace property");
                    return null;
                }
                var ns = namespaceElement.GetString();

                if (!metadata.TryGetProperty("uid", out var uidElement))
                {
                    _logger.LogWarning("Metadata doesn't contain uid property");
                    return null;
                }
                var uid = uidElement.GetString();

                DateTime creationTimestamp = DateTime.UtcNow;
                if (metadata.TryGetProperty("creationTimestamp", out var creationTimestampElement))
                {
                    DateTime.TryParse(creationTimestampElement.GetString(), out creationTimestamp);
                }

                var rootProps = new List<string>();
                foreach (var prop in reportElement.EnumerateObject())
                {
                    rootProps.Add(prop.Name);
                }
                _logger.LogDebug($"Root properties: {string.Join(", ", rootProps)}");

                string imageName = null;
                string imageTag = "latest";
                var vulnerabilities = new List<VulnerabilityItem>();
                var processedVulns = 0;
                var skippedVulns = 0;

                // Verificar se o relatório existe
                if (reportElement.TryGetProperty("report", out var report))
                {
                    var reportProps = new List<string>();
                    foreach (var prop in report.EnumerateObject())
                    {
                        reportProps.Add(prop.Name);
                    }
                    _logger.LogDebug($"Report properties: {string.Join(", ", reportProps)}");

                    if (report.TryGetProperty("artifact", out var artifact))
                    {
                        if (artifact.TryGetProperty("repository", out var repositoryElement))
                        {
                            imageName = repositoryElement.GetString();

                            if (artifact.TryGetProperty("tag", out var tagElement))
                            {
                                imageTag = tagElement.GetString() ?? "latest";
                            }

                            _logger.LogDebug($"Found image from artifact: {imageName}:{imageTag}");
                        }
                    }
                    else if (report.TryGetProperty("registry", out var registryElement) &&
                             report.TryGetProperty("target", out var targetElement))
                    {
                        var registry = registryElement.GetString() ?? "";
                        var target = targetElement.GetString() ?? "";

                        if (!string.IsNullOrEmpty(registry) && !string.IsNullOrEmpty(target))
                        {
                            imageName = $"{registry}/{target}";

                            if (report.TryGetProperty("tag", out var tagElement))
                            {
                                imageTag = tagElement.GetString() ?? "latest";
                            }

                            _logger.LogDebug($"Found image from registry/target: {imageName}:{imageTag}");
                        }
                    }

                    JsonElement vulnsElement;
                    bool hasVulnerabilities = false;

                    if (report.TryGetProperty("vulnerabilities", out vulnsElement) &&
                        vulnsElement.ValueKind == JsonValueKind.Array)
                    {
                        hasVulnerabilities = true;
                        _logger.LogDebug($"Found vulnerabilities at report.vulnerabilities");
                    }
                    else if (report.TryGetProperty("results", out var resultsElement) &&
                             resultsElement.ValueKind == JsonValueKind.Array)
                    {
                        
                        foreach (var resultElement in resultsElement.EnumerateArray())
                        {
                            if (resultElement.TryGetProperty("vulnerabilities", out vulnsElement) &&
                                vulnsElement.ValueKind == JsonValueKind.Array)
                            {
                                hasVulnerabilities = true;
                                _logger.LogDebug($"Found vulnerabilities at report.results[].vulnerabilities");
                                break;
                            }
                        }
                    }
                    else if (reportElement.TryGetProperty("vulnerabilities", out vulnsElement) &&
                             vulnsElement.ValueKind == JsonValueKind.Array)
                    {
                        hasVulnerabilities = true;
                        _logger.LogDebug($"Found vulnerabilities at root.vulnerabilities");
                    }

                    // Processar vulnerabilidades se encontradas
                    if (hasVulnerabilities && vulnsElement.ValueKind == JsonValueKind.Array)
                    {
                        int vulnCount = vulnsElement.GetArrayLength();
                        _logger.LogDebug($"Processing {vulnCount} vulnerabilities");

                        if (vulnCount > 0)
                        {
                            var firstVuln = vulnsElement[0];
                            _logger.LogDebug($"First vulnerability example: {firstVuln.ToString()}");

                            var vulnProps = new List<string>();
                            foreach (var prop in firstVuln.EnumerateObject())
                            {
                                vulnProps.Add(prop.Name);
                            }
                            _logger.LogDebug($"Vulnerability properties: {string.Join(", ", vulnProps)}");
                        }

                        foreach (var vulnElement in vulnsElement.EnumerateArray())
                        {
                            try
                            {
                                string vulnId = null;
                                string packageName = null;
                                string installedVersion = null;
                                string fixedVersion = null;
                                string severityStr = "Unknown";
                                string description = null;
                                var references = new List<string>();
                                double? cvssScore = null;

                                // VulnerabilityID
                                if (vulnElement.TryGetProperty("vulnerabilityID", out var vulnIdElement))
                                    vulnId = vulnIdElement.GetString();

                                // Package Name (resource ou packageName)
                                if (vulnElement.TryGetProperty("resource", out var resourceElement))
                                    packageName = resourceElement.GetString();
                                else if (vulnElement.TryGetProperty("packageName", out var packageNameElement))
                                    packageName = packageNameElement.GetString();

                                // Versão instalada
                                if (vulnElement.TryGetProperty("installedVersion", out var versionElement))
                                    installedVersion = versionElement.GetString();

                                // Versão fixa
                                if (vulnElement.TryGetProperty("fixedVersion", out var fixedVersionElement))
                                    fixedVersion = fixedVersionElement.GetString();

                                // Severidade
                                if (vulnElement.TryGetProperty("severity", out var severityElement))
                                    severityStr = severityElement.GetString() ?? "Unknown";

                                // Descrição (title)
                                if (vulnElement.TryGetProperty("title", out var titleElement))
                                    description = titleElement.GetString();

                                // Links (primaryLink ou links[])
                                if (vulnElement.TryGetProperty("primaryLink", out var primaryLinkElement))
                                {
                                    var link = primaryLinkElement.GetString();
                                    if (!string.IsNullOrEmpty(link))
                                        references.Add(link);
                                }

                                if (vulnElement.TryGetProperty("links", out var linksElement) &&
                                    linksElement.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var linkElement in linksElement.EnumerateArray())
                                    {
                                        if (linkElement.ValueKind == JsonValueKind.String)
                                        {
                                            var link = linkElement.GetString();
                                            if (!string.IsNullOrEmpty(link))
                                                references.Add(link);
                                        }
                                    }
                                }

                                if (vulnElement.TryGetProperty("score", out var scoreElement) &&
                                    scoreElement.ValueKind == JsonValueKind.Number)
                                {
                                    cvssScore = scoreElement.GetDouble();
                                }

                                // Verificar se temos os campos mínimos necessários
                                if (string.IsNullOrEmpty(vulnId) || string.IsNullOrEmpty(packageName) ||
                                    string.IsNullOrEmpty(installedVersion))
                                {
                                    var missingFields = new List<string>();
                                    if (string.IsNullOrEmpty(vulnId)) missingFields.Add("vulnerabilityID");
                                    if (string.IsNullOrEmpty(packageName)) missingFields.Add("resource/packageName");
                                    if (string.IsNullOrEmpty(installedVersion)) missingFields.Add("installedVersion");

                                    _logger.LogWarning($"Vulnerability is missing required fields: {string.Join(", ", missingFields)}");
                                    skippedVulns++;
                                    continue;
                                }

                                VulnerabilitySeverity severity;
                                if (!Enum.TryParse<VulnerabilitySeverity>(severityStr, true, out severity))
                                {
                                    _logger.LogWarning($"Unknown severity: {severityStr}, using Unknown");
                                    severity = VulnerabilitySeverity.Unknown;
                                }

                                // Adicionar vulnerabilidade à lista
                                vulnerabilities.Add(new VulnerabilityItem
                                {
                                    VulnerabilityID = vulnId,
                                    PkgName = packageName,
                                    InstalledVersion = installedVersion,
                                    FixedVersion = fixedVersion,
                                    Severity = severity,
                                    Description = description,
                                    References = references,
                                    CvssScore = cvssScore
                                });

                                processedVulns++;
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Error parsing individual vulnerability");
                                skippedVulns++;
                            }
                        }
                    }
                    else
                    {
                        _logger.LogWarning("No vulnerabilities found in the report");
                    }
                }
                else
                {
                    _logger.LogWarning("Report element doesn't contain report property");
                }

                if (string.IsNullOrEmpty(imageName))
                {
                    _logger.LogWarning($"Couldn't extract image name from report, using report name as fallback: {name}");
                    imageName = name;
                }

                var fullImageName = string.IsNullOrEmpty(imageTag) ? imageName : $"{imageName}:{imageTag}";
                _logger.LogInformation($"Processed {processedVulns} vulnerabilities, skipped {skippedVulns} for image {fullImageName}");

                // Criar e retornar o relatório
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
                return null;
            }
        }

        private ConfigAuditReportResource DeserializeConfigAuditReport(JsonElement reportElement)
        {
            try
            {
                if (!reportElement.TryGetProperty("metadata", out var metadata))
                {
                    _logger.LogWarning("Config audit report doesn't contain metadata property");
                    return null;
                }

                if (!metadata.TryGetProperty("name", out var nameElement) ||
                    !metadata.TryGetProperty("namespace", out var namespaceElement) ||
                    !metadata.TryGetProperty("uid", out var uidElement))
                {
                    _logger.LogWarning("Config audit report metadata missing required fields");
                    return null;
                }

                var name = nameElement.GetString();
                var ns = namespaceElement.GetString();
                var uid = uidElement.GetString();

                DateTime creationTimestamp = DateTime.UtcNow;
                if (metadata.TryGetProperty("creationTimestamp", out var creationTimestampElement))
                {
                    DateTime.TryParse(creationTimestampElement.GetString(), out creationTimestamp);
                }

                if (!reportElement.TryGetProperty("report", out var report))
                {
                    _logger.LogWarning("Config audit report doesn't contain report property");
                    return null;
                }

                int lowCount = 0, mediumCount = 0, highCount = 0, criticalCount = 0;
                if (report.TryGetProperty("summary", out var summary))
                {
                    if (summary.TryGetProperty("lowCount", out var lowElement))
                        lowCount = lowElement.GetInt32();
                    if (summary.TryGetProperty("mediumCount", out var mediumElement))
                        mediumCount = mediumElement.GetInt32();
                    if (summary.TryGetProperty("highCount", out var highElement))
                        highCount = highElement.GetInt32();
                    if (summary.TryGetProperty("criticalCount", out var criticalElement))
                        criticalCount = criticalElement.GetInt32();
                }

                var checks = new List<ConfigAuditCheck>();
                if (report.TryGetProperty("checks", out var checksElement) &&
                    checksElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var checkElement in checksElement.EnumerateArray())
                    {
                        try
                        {
                            if (!checkElement.TryGetProperty("checkID", out var checkIdElement) ||
                                !checkElement.TryGetProperty("severity", out var severityElement) ||
                                !checkElement.TryGetProperty("success", out var successElement))
                            {
                                _logger.LogWarning("Config audit check missing required fields, skipping");
                                continue;
                            }

                            var check = new ConfigAuditCheck
                            {
                                ID = checkIdElement.GetString(),
                                Title = checkElement.TryGetProperty("title", out var titleElement) ?
                                    titleElement.GetString() : checkIdElement.GetString(),
                                Severity = ParseSeverity(severityElement.GetString()),
                                Category = checkElement.TryGetProperty("category", out var catElement) ?
                                    catElement.GetString() : null,
                                Description = checkElement.TryGetProperty("description", out var descElement) ?
                                    descElement.GetString() : null,
                                Success = successElement.GetBoolean()
                            };

                            checks.Add(check);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Error parsing individual config audit check");
                        }
                    }
                }

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
                return null;
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
