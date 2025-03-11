using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace ComplianceMonitor.Infrastructure.Data.Repositories
{
    public class AlertRepository : IAlertRepository
    {
        private readonly ComplianceDbContext _context;

        public AlertRepository(ComplianceDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task AddAsync(Alert alert, CancellationToken cancellationToken = default)
        {
            await _context.Alerts.AddAsync(alert, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task<IEnumerable<Alert>> GetUnacknowledgedAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Alerts
                .Include(a => a.ComplianceCheck)
                    .ThenInclude(c => c.Policy)
                .Include(a => a.ComplianceCheck)
                    .ThenInclude(c => c.Resource)
                .Where(a => !a.Acknowledged)
                .ToListAsync(cancellationToken);
        }

        public async Task UpdateAsync(Alert alert, CancellationToken cancellationToken = default)
        {
            _context.Alerts.Update(alert);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
}