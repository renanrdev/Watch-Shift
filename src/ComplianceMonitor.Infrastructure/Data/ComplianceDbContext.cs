using System;
using System.Text.Json;
using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace ComplianceMonitor.Infrastructure.Data
{
    public class ComplianceDbContext : DbContext
    {
        public DbSet<Policy> Policies { get; set; }
        public DbSet<KubernetesResource> Resources { get; set; }
        public DbSet<ComplianceCheck> Checks { get; set; }
        public DbSet<Alert> Alerts { get; set; }
        public DbSet<ImageScanResult> ImageScans { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }

        public ComplianceDbContext(DbContextOptions<ComplianceDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Apply configurations
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ComplianceDbContext).Assembly);

            // Configure ValueConverters for JsonSerializable properties
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };

            ValueConverter<Dictionary<string, object>, string> dictionaryConverter =
                new ValueConverter<Dictionary<string, object>, string>(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, jsonOptions)
                         ?? new Dictionary<string, object>());

            ValueConverter<Dictionary<string, string>, string> stringDictionaryConverter =
                new ValueConverter<Dictionary<string, string>, string>(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, jsonOptions)
                         ?? new Dictionary<string, string>());

            ValueConverter<List<string>, string> stringListConverter =
                new ValueConverter<List<string>, string>(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions)
                         ?? new List<string>());

            ValueComparer<Dictionary<string, object>> dictionaryComparer =
                new ValueComparer<Dictionary<string, object>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c.GetHashCode(),
                    c => JsonSerializer.Deserialize<Dictionary<string, object>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)
                         ?? new Dictionary<string, object>());

            ValueComparer<Dictionary<string, string>> stringDictionaryComparer =
                new ValueComparer<Dictionary<string, string>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c.GetHashCode(),
                    c => JsonSerializer.Deserialize<Dictionary<string, string>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)
                         ?? new Dictionary<string, string>());

            ValueComparer<List<string>> stringListComparer =
                new ValueComparer<List<string>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c.GetHashCode(),
                    c => JsonSerializer.Deserialize<List<string>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)
                         ?? new List<string>());

            // Apply converters to entities
            modelBuilder.Entity<Policy>()
                .Property(p => p.Parameters)
                .HasConversion(dictionaryConverter)
                .Metadata.SetValueComparer(dictionaryComparer);

            modelBuilder.Entity<KubernetesResource>()
                .Property(r => r.Labels)
                .HasConversion(stringDictionaryConverter)
                .Metadata.SetValueComparer(stringDictionaryComparer);

            modelBuilder.Entity<KubernetesResource>()
                .Property(r => r.Annotations)
                .HasConversion(stringDictionaryConverter)
                .Metadata.SetValueComparer(stringDictionaryComparer);

            modelBuilder.Entity<KubernetesResource>()
                .Property(r => r.Spec)
                .HasConversion(dictionaryConverter)
                .Metadata.SetValueComparer(dictionaryComparer);

            modelBuilder.Entity<ComplianceCheck>()
                .Property(c => c.Details)
                .HasConversion(dictionaryConverter)
                .Metadata.SetValueComparer(dictionaryComparer);

            modelBuilder.Entity<ImageScanResult>()
                .Property(i => i.Metadata)
                .HasConversion(dictionaryConverter)
                .Metadata.SetValueComparer(dictionaryComparer);

            modelBuilder.Entity<Vulnerability>()
                .Property(v => v.References)
                .HasConversion(stringListConverter)
                .Metadata.SetValueComparer(stringListComparer);
        }
    }
}