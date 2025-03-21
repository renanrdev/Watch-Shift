using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScansController : ControllerBase
    {
        private readonly IScanService _scanService;
        private readonly ILogger<ScansController> _logger;
        private readonly IWebHostEnvironment _environment;

        public ScansController(
            IScanService scanService,
            ILogger<ScansController> logger,
            IWebHostEnvironment environment)
        {
            _scanService = scanService ?? throw new ArgumentNullException(nameof(scanService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _environment = environment ?? throw new ArgumentNullException(nameof(environment));
        }

        [HttpPost]
        public async Task<ActionResult<ImageScanResultDto>> ScanImage(ScanRequestDto scanRequest, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await _scanService.ScanImageAsync(scanRequest.ImageName, scanRequest.Force, cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error scanning image {scanRequest.ImageName}");
                return StatusCode(500, new { error = $"Failed to scan image: {ex.Message}" });
            }
        }

        [HttpPost("batch")]
        public async Task<ActionResult<BatchScanResultDto>> ScanAllImages([FromQuery] bool force = false, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await _scanService.ScanAllImagesAsync(force, cancellationToken);

                // Em ambiente de desenvolvimento utilizar imagens padrões
                if (result.ScannedImages == 0 && _environment.IsDevelopment())
                {
                    // Adicionar sugestões ao resultado
                    var suggestions = new List<string> {
                        "nginx:latest",
                        "registry.access.redhat.com/ubi8/ubi-minimal:latest",
                        "mcr.microsoft.com/dotnet/aspnet:8.0"
                    };

                    _logger.LogInformation("No images found to scan. In development, you can try scanning specific test images");

                    result.Status = "completed_with_suggestions";
                    result.Error = "No images were found in the cluster. You can try scanning specific test images manually.";
                    result.ImageList = suggestions;
                }

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in batch scan");
                return StatusCode(500, new { error = $"Failed to perform batch scan: {ex.Message}" });
            }
        }

        [HttpGet("namespace/{namespace}")]
        public async Task<ActionResult<NamespaceScanSummaryDto>> GetNamespaceVulnerabilities(string @namespace, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await _scanService.GetNamespaceVulnerabilitiesAsync(@namespace, cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting vulnerabilities for namespace {@namespace}");
                return StatusCode(500, new { error = $"Failed to get namespace vulnerabilities: {ex.Message}" });
            }
        }

        [HttpGet("{imageName}")]
        public async Task<ActionResult<ImageScanResultDto>> GetImageScan(string imageName, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await _scanService.GetImageScanAsync(imageName, cancellationToken);
                return Ok(result);
            }
            catch (KeyNotFoundException)
            {
                return NotFound(new { error = $"No scan results found for image: {imageName}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting scan results for {imageName}");
                return StatusCode(500, new { error = $"Failed to get scan results: {ex.Message}" });
            }
        }

        [HttpGet("test-trivy")]
        public async Task<ActionResult<Dictionary<string, object>>> TestTrivy(CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await _scanService.TestTrivyAsync(cancellationToken);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing Trivy connection");
                return StatusCode(500, new
                {
                    error = $"Failed to test Trivy connection: {ex.Message}",
                    status = "error",
                    trivy_available = false
                });
            }
        }
    }
}