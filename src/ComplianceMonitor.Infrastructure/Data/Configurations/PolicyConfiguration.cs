using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ComplianceMonitor.Infrastructure.Data.Configurations
{
    public class PolicyConfiguration : IEntityTypeConfiguration<Policy>
    {
        public void Configure(EntityTypeBuilder<Policy> builder)
        {
            builder.ToTable("Policies");

            builder.HasKey(p => p.Id);

            builder.Property(p => p.Name)
                .IsRequired()
                .HasMaxLength(100);

            builder.Property(p => p.Description)
                .HasMaxLength(500);

            builder.Property(p => p.Severity)
                .IsRequired()
                .HasConversion<string>();

            builder.Property(p => p.RuleType)
                .IsRequired()
                .HasConversion<string>();

            builder.Property(p => p.IsEnabled)
                .IsRequired();

            builder.Property(p => p.CreatedAt)
                .IsRequired();

            builder.Property(p => p.UpdatedAt)
                .IsRequired();

            // Relationships
            builder.HasMany<ComplianceCheck>()
                .WithOne(c => c.Policy)
                .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            builder.HasIndex(p => p.Name);
            builder.HasIndex(p => p.IsEnabled);
            builder.HasIndex(p => p.RuleType);
        }
    }
}