using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;

namespace ComplianceMonitor.Application.Interfaces
{
    public interface IScanService
    {
        Task<ImageScanResultDto> ScanImageAsync(string imageName, bool force = false, CancellationToken cancellationToken = default);
        Task<BatchScanResultDto> ScanAllImagesAsync(bool force = false, CancellationToken cancellationToken = default);
        Task<NamespaceScanSummaryDto> GetNamespaceVulnerabilitiesAsync(string @namespace, CancellationToken cancellationToken = default);
        Task<ImageScanResultDto> GetImageScanAsync(string imageName, CancellationToken cancellationToken = default);
        Task<Dictionary<string, object>> TestTrivyAsync(CancellationToken cancellationToken = default);
    }
}
