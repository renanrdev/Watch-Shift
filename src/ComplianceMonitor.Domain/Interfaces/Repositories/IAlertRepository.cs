using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Domain.Interfaces.Repositories
{
    public interface IAlertRepository
    {
        Task AddAsync(Alert alert, CancellationToken cancellationToken = default);
        Task<IEnumerable<Alert>> GetUnacknowledgedAsync(CancellationToken cancellationToken = default);
        Task UpdateAsync(Alert alert, CancellationToken cancellationToken = default);
    }
}