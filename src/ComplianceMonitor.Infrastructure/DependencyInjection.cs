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

            // Trivy scanners
            services.Configure<TrivyScannerOptions>(configuration.GetSection("Trivy"));
            services.Configure<TrivyOperatorScannerOptions>(configuration.GetSection("TrivyOperator"));
            services.AddSingleton<IVulnerabilityScanner, TrivyScanner>();
            services.AddSingleton<IVulnerabilityScanner, TrivyOperatorScanner>();

            // Background services
            services.AddHostedService<ScanBackgroundService>();

            return services;
        }

        public static IServiceCollection AddApplication(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAutoMapper(typeof(MappingProfile));

            // Application services
            services.AddScoped<IPolicyEngine, PolicyEngine>();
            services.AddScoped<IPolicyService, PolicyService>();
            services.AddScoped<IScanService, ScanService>();
            services.AddScoped<IDashboardService, DashboardService>();

            services.Configure<ScanServiceOptions>(options => {
                options.ScanIntervalHours = configuration.GetValue<int>("Trivy:ScanIntervalHours", 24);
                options.UseOperatorScanner = configuration.GetValue<bool>("TrivyOperator:Enabled", true);

                var isDevelopment = configuration.GetValue<bool>("IsDevelopmentEnvironment", false);
                options.AddDefaultImagesInDev = isDevelopment &&
                                               configuration.GetValue<bool>("Trivy:AddDefaultImagesInDev", false);

                if (options.AddDefaultImagesInDev)
                {
                    var defaultImages = configuration.GetSection("Trivy:DefaultImages").Get<List<string>>();
                    if (defaultImages != null && defaultImages.Any())
                    {
                        options.DefaultImages = defaultImages;
                    }
                }
            });

            services.Configure<DashboardServiceOptions>(options => {
                options.UseTrivyOperator = configuration.GetValue<bool>("TrivyOperator:Enabled", true);
            });

            return services;
        }
    }
}