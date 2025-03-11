using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Domain.Interfaces.Repositories
{
    public interface IComplianceCheckRepository
    {
        Task AddAsync(ComplianceCheck check, CancellationToken cancellationToken = default);
        Task<ComplianceCheck> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<IEnumerable<ComplianceCheck>> GetNonCompliantAsync(CancellationToken cancellationToken = default);
        Task<IEnumerable<ComplianceCheck>> GetAllAsync(int limit = 100, int offset = 0, CancellationToken cancellationToken = default);
    }
}