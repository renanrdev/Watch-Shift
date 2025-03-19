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
    public class ResourceRepository : IResourceRepository
    {
        private readonly ComplianceDbContext _context;

        public ResourceRepository(ComplianceDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task<Guid> AddAsync(KubernetesResource resource, CancellationToken cancellationToken = default)
        {
            var existing = await _context.Resources
                .FirstOrDefaultAsync(r => r.Uid == resource.Uid, cancellationToken);

            if (existing != null)
            {
                return existing.Id;
            }

            // Add new resource
            await _context.Resources.AddAsync(resource, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            return resource.Id;
        }

        public async Task<KubernetesResource> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.Resources.FindAsync(new object[] { id }, cancellationToken);
        }

        public async Task<KubernetesResource> GetByUidAsync(string uid, CancellationToken cancellationToken = default)
        {
            return await _context.Resources
                .FirstOrDefaultAsync(r => r.Uid == uid, cancellationToken);
        }

        public async Task<IEnumerable<KubernetesResource>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            return await _context.Resources.ToListAsync(cancellationToken);
        }
    }
}