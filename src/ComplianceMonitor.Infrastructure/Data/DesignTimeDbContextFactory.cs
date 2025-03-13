// ComplianceMonitor.Infrastructure/Data/DesignTimeDbContextFactory.cs
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace ComplianceMonitor.Infrastructure.Data
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ComplianceDbContext>
    {
        public ComplianceDbContext CreateDbContext(string[] args)
        {
            var basePath = Directory.GetCurrentDirectory();

            // Navegar até a pasta do projeto API
            var configPath = Path.Combine(basePath, "..", "ComplianceMonitor.Api");

            var configuration = new ConfigurationBuilder()
                .SetBasePath(configPath)
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile("appsettings.Development.json", optional: true)
                .Build();

            var builder = new DbContextOptionsBuilder<ComplianceDbContext>();

            var connectionString = "Host=localhost;Database=ComplianceMonitorDb_Dev;Username=postgres;Password=sua_senha";

            builder.UseNpgsql(connectionString,
                b => b.MigrationsAssembly(typeof(ComplianceDbContext).Assembly.FullName));

            return new ComplianceDbContext(builder.Options);
        }
    }
}