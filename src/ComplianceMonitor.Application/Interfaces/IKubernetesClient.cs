using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Application.Interfaces
{
    public interface IKubernetesClient
    {
        Task<bool> CheckConnectionAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<KubernetesResource>> GetNamespacesAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<KubernetesResource>> GetSccsAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<KubernetesResource>> GetPodsAsync(string @namespace = null, CancellationToken cancellationToken = default);
        Task<IEnumerable<KubernetesResource>> GetAllPodsAsync(CancellationToken cancellationToken = default);

        // Novos métodos para o Trivy Operator
        Task<IEnumerable<VulnerabilityReportResource>> GetVulnerabilityReportsAsync(string @namespace = null, CancellationToken cancellationToken = default);
        Task<VulnerabilityReportResource> GetVulnerabilityReportAsync(string name, string @namespace, CancellationToken cancellationToken = default);
        Task<IEnumerable<ConfigAuditReportResource>> GetConfigAuditReportsAsync(string @namespace = null, CancellationToken cancellationToken = default);
    }
}