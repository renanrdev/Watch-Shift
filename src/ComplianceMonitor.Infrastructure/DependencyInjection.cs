using System;
using AutoMapper;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Application.Mapping;
using ComplianceMonitor.Application.Services;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using ComplianceMonitor.Domain.Interfaces.Services;
using ComplianceMonitor.Infrastructure.Background;
using ComplianceMonitor.Infrastructure.Data;
using ComplianceMonitor.Infrastructure.Data.Repositories;
using ComplianceMonitor.Infrastructure.Kubernetes;
using ComplianceMonitor.Infrastructure.Scanners;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ComplianceMonitor.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            // Database configuration
            services.AddDbContext<ComplianceDbContext>(options =>
                options.UseNpgsql(
                    configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly(typeof(ComplianceDbContext).Assembly.FullName)));

            // Repositories
            services.AddScoped<IPolicyRepository, PolicyRepository>();
            services.AddScoped<IResourceRepository, ResourceRepository>();
            services.AddScoped<IComplianceCheckRepository, ComplianceCheckRepository>();
            services.AddScoped<IAlertRepository, AlertRepository>();
            services.AddScoped<IImageScanRepository, ImageScanRepository>();

            // Kubernetes client
            services.Configure<KubernetesClientOptions>(configuration.GetSection("Kubernetes"));
            services.AddSingleton<IKubernetesClient, KubernetesClient>();

            // Trivy scanner
            services.Configure<TrivyScannerOptions>(configuration.GetSection("Trivy"));
            services.AddSingleton<IVulnerabilityScanner, TrivyScanner>();

            // Background services
            services.AddHostedService<ScanBackgroundService>();

            return services;
        }

        public static IServiceCollection AddApplication(this IServiceCollection services, IConfiguration configuration)
        {
            // AutoMapper configuration
            services.AddAutoMapper(typeof(MappingProfile));

            // Application services
            services.AddScoped<IPolicyEngine, PolicyEngine>();
            services.AddScoped<IPolicyService, PolicyService>();
            services.AddScoped<IScanService, ScanService>();
            services.AddScoped<IDashboardService, DashboardService>();

            // Configuration for ScanService
            services.AddSingleton(sp => new ScanServiceOptions
            {
                ScanIntervalHours = configuration.GetValue<int>("Trivy:ScanIntervalHours", 24)
            });

            return services;
        }
    }

    public class ScanServiceOptions
    {
        public int ScanIntervalHours { get; set; } = 24;
    }
}