using System;
using System.Collections.Generic;
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
    public class ScansController : ControllerBase
    {
        private readonly IScanService _scanService;

        public ScansController(IScanService scanService)
        {
            _scanService = scanService ?? throw new ArgumentNullException(nameof(scanService));
        }

        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ImageScanResultDto>> ScanImage(ScanRequestDto scanRequest, CancellationToken cancellationToken = default)
        {
            var result = await _scanService.ScanImageAsync(scanRequest.ImageName, scanRequest.Force, cancellationToken);
            return Ok(result);
        }

        [HttpPost("batch")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<BatchScanResultDto>> ScanAllImages([FromQuery] bool force = false, CancellationToken cancellationToken = default)
        {
            var result = await _scanService.ScanAllImagesAsync(force, cancellationToken);
            return Ok(result);
        }

        [HttpGet("namespace/{namespace}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<NamespaceScanSummaryDto>> GetNamespaceVulnerabilities(string @namespace, CancellationToken cancellationToken = default)
        {
            var result = await _scanService.GetNamespaceVulnerabilitiesAsync(@namespace, cancellationToken);
            return Ok(result);
        }

        [HttpGet("{imageName}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<ImageScanResultDto>> GetImageScan(string imageName, CancellationToken cancellationToken = default)
        {
            var result = await _scanService.GetImageScanAsync(imageName, cancellationToken);
            return Ok(result);
        }

        [HttpGet("test-trivy")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<Dictionary<string, object>>> TestTrivy(CancellationToken cancellationToken = default)
        {
            var result = await _scanService.TestTrivyAsync(cancellationToken);
            return Ok(result);
        }
    }
}
