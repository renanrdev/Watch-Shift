using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
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
    }

    public class KubernetesClientOptions
    {
        public string ApiUrl { get; set; }
        public string Token { get; set; }
        public string KubeconfigPath { get; set; } = "~/.kube/config";
        public bool VerifySsl { get; set; } = true;
    }
}