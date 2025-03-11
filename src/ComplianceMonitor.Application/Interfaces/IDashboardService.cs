using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;

namespace ComplianceMonitor.Application.Interfaces
{
    public interface IDashboardService
    {
        Task<DashboardDto> GetDashboardDataAsync(CancellationToken cancellationToken = default);
    }
}