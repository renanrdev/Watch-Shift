using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ComplianceMonitor.Infrastructure.Data.Configurations
{
    public class ImageScanResultConfiguration : IEntityTypeConfiguration<ImageScanResult>
    {
        public void Configure(EntityTypeBuilder<ImageScanResult> builder)
        {
            builder.ToTable("ImageScans");

            builder.HasKey(i => i.Id);

            builder.Property(i => i.ImageName)
                .IsRequired()
                .HasMaxLength(500);

            builder.Property(i => i.ScanTime)
                .IsRequired();

            // Relationships
            builder.HasMany(i => i.Vulnerabilities)
                .WithOne()
                .HasForeignKey("ImageScanResultId")
                .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            builder.HasIndex(i => i.ImageName);
        }
    }
}