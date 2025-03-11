using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Domain.Interfaces.Repositories
{
    public interface IPolicyRepository
    {
        Task<Policy> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<IEnumerable<Policy>> GetAllAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<Policy>> GetAllEnabledAsync(CancellationToken cancellationToken = default);
        Task AddAsync(Policy policy, CancellationToken cancellationToken = default);
        Task UpdateAsync(Policy policy, CancellationToken cancellationToken = default);
        Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
    }
}
