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
    }
}