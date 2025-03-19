using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ComplianceMonitor.Infrastructure.Data.Configurations
{
    public class ComplianceCheckConfiguration : IEntityTypeConfiguration<ComplianceCheck>
    {
        public void Configure(EntityTypeBuilder<ComplianceCheck> builder)
        {
            builder.ToTable("ComplianceChecks");

            builder.HasKey(c => c.Id);

            builder.Property(c => c.Status)
                .IsRequired()
                .HasConversion<string>();

            builder.Property(c => c.Timestamp)
                .IsRequired();

            builder.HasOne(c => c.Policy)
                .WithMany()
                .HasForeignKey("PolicyId")
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasOne(c => c.Resource)
                .WithMany()
                .HasForeignKey("ResourceId")
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasMany<Alert>()
                .WithOne(a => a.ComplianceCheck)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasIndex("PolicyId");
            builder.HasIndex("ResourceId");
            builder.HasIndex(c => c.Status);
        }
    }
}