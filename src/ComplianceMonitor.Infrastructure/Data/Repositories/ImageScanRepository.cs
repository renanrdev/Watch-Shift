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
    public class ImageScanRepository : IImageScanRepository
    {
        private readonly ComplianceDbContext _context;

        public ImageScanRepository(ComplianceDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task AddAsync(ImageScanResult scanResult, CancellationToken cancellationToken = default)
        {
            foreach (var vulnerability in scanResult.Vulnerabilities)
            {
                vulnerability.SetImageScanResultId(scanResult.Id);
            }

            await _context.ImageScans.AddAsync(scanResult, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        public async Task<ImageScanResult> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
        }

        public async Task<IEnumerable<ImageScanResult>> GetByImageNameAsync(string imageName, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .Where(s => s.ImageName == imageName)
                .OrderByDescending(s => s.ScanTime)
                .ToListAsync(cancellationToken);
        }

        public async Task<ImageScanResult> GetLatestByImageNameAsync(string imageName, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .Where(s => s.ImageName == imageName)
                .OrderByDescending(s => s.ScanTime)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<IEnumerable<ImageScanResult>> GetAllAsync(int limit = 100, int offset = 0, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .OrderByDescending(s => s.ScanTime)
                .Skip(offset)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }
    }
}