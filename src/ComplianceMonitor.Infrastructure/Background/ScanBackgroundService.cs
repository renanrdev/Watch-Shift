using System;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ComplianceMonitor.Infrastructure.Background
{
    public class ScanBackgroundService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<ScanBackgroundService> _logger;
        private readonly ScanBackgroundServiceOptions _options;

        public ScanBackgroundService(
            IServiceProvider serviceProvider,
            IOptions<ScanBackgroundServiceOptions> options,
            ILogger<ScanBackgroundService> logger)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
            _options = options?.Value ?? new ScanBackgroundServiceOptions();
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Scan Background Service is starting");

            await Task.Delay(TimeSpan.FromMinutes(_options.InitialDelayMinutes), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("Starting scheduled scan of all images");

                try
                {
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var scanService = scope.ServiceProvider.GetRequiredService<IScanService>();

                        var result = await scanService.ScanAllImagesAsync(
                            force: _options.ForceScans,
                            cancellationToken: stoppingToken);

                        _logger.LogInformation(
                            "Scheduled scan completed: {Status}, Scanned: {ScannedCount}, Vulnerabilities found: {@VulnerabilityCounts}",
                            result.Status,
                            result.ScannedImages,
                            result.VulnerabilityCounts);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error performing scheduled scan");
                }

                var intervalMinutes = Math.Max(1, _options.ScanIntervalMinutes);
                _logger.LogInformation("Next scan scheduled after {IntervalMinutes} minutes", intervalMinutes);
                await Task.Delay(TimeSpan.FromMinutes(intervalMinutes), stoppingToken);
            }

            _logger.LogInformation("Scan Background Service is stopping");
        }
    }

    public class ScanBackgroundServiceOptions
    {
        public int InitialDelayMinutes { get; set; } = 5;
        public int ScanIntervalMinutes { get; set; } = 360; // 6 horas
        public bool ForceScans { get; set; } = false;
    }
}