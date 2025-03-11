using System;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ComplianceMonitor.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DashboardController : ControllerBase
    {
        private readonly IDashboardService _dashboardService;

        public DashboardController(IDashboardService dashboardService)
        {
            _dashboardService = dashboardService ?? throw new ArgumentNullException(nameof(dashboardService));
        }

        [HttpGet]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<DashboardDto>> GetDashboardData(CancellationToken cancellationToken = default)
        {
            var data = await _dashboardService.GetDashboardDataAsync(cancellationToken);
            return Ok(data);
        }
    }
}