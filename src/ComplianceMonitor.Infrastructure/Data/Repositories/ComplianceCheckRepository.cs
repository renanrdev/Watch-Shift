using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;

namespace ComplianceMonitor.Infrastructure.Data.Repositories
{
    public class ComplianceCheckRepository : IComplianceCheckRepository
    {
        private readonly ComplianceDbContext _context;

        public ComplianceCheckRepository(ComplianceDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task AddAsync(ComplianceCheck check, CancellationToken cancellationToken = default)
        {
            await _context.Checks.AddAsync(check, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task<ComplianceCheck> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.Checks
                .Include(c => c.Policy)
                .Include(c => c.Resource)
                .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        }

        public async Task<IEnumerable<ComplianceCheck>> GetNonCompliantAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Checks
                .Include(c => c.Policy)
                .Include(c => c.Resource)
                .Where(c => c.Status != ComplianceStatus.Compliant)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<ComplianceCheck>> GetAllAsync(int limit = 100, int offset = 0, CancellationToken cancellationToken = default)
        {
            return await _context.Checks
                .Include(c => c.Policy)
                .Include(c => c.Resource)
                .OrderByDescending(c => c.Timestamp)
                .Skip(offset)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }
    }
}