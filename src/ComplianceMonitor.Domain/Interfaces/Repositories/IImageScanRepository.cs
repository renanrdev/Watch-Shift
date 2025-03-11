using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;

namespace ComplianceMonitor.Domain.Interfaces.Repositories
{
    public interface IImageScanRepository
    {
        Task AddAsync(ImageScanResult scanResult, CancellationToken cancellationToken = default);
        Task<ImageScanResult> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<IEnumerable<ImageScanResult>> GetByImageNameAsync(string imageName, CancellationToken cancellationToken = default);
        Task<ImageScanResult> GetLatestByImageNameAsync(string imageName, CancellationToken cancellationToken = default);
        Task<IEnumerable<ImageScanResult>> GetAllAsync(int limit = 100, int offset = 0, CancellationToken cancellationToken = default);
    }
}