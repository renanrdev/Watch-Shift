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
    public class PolicyRepository : IPolicyRepository
    {
        private readonly ComplianceDbContext _context;

        public PolicyRepository(ComplianceDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task<Policy> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.Policies.FindAsync(new object[] { id }, cancellationToken);
        }

        public async Task<IEnumerable<Policy>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Policies.ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<Policy>> GetAllEnabledAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Policies
                .Where(p => p.IsEnabled)
                .ToListAsync(cancellationToken);
        }

        public async Task AddAsync(Policy policy, CancellationToken cancellationToken = default)
        {
            await _context.Policies.AddAsync(policy, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task UpdateAsync(Policy policy, CancellationToken cancellationToken = default)
        {
            _context.Policies.Update(policy);
            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var policy = await _context.Policies.FindAsync(new object[] { id }, cancellationToken);
            if (policy != null)
            {
                _context.Policies.Remove(policy);
                await _context.SaveChangesAsync(cancellationToken);
            }
        }
    }
}