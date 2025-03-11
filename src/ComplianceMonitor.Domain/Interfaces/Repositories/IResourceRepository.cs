using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Domain.Interfaces.Repositories
{
    public interface IResourceRepository
    {
        Task<Guid> AddAsync(KubernetesResource resource, CancellationToken cancellationToken = default);
        Task<KubernetesResource> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<KubernetesResource> GetByUidAsync(string uid, CancellationToken cancellationToken = default);
        Task<IEnumerable<KubernetesResource>> GetAllAsync(CancellationToken cancellationToken = default);
    }
}