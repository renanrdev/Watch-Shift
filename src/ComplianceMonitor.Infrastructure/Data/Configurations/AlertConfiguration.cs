using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ComplianceMonitor.Infrastructure.Data.Configurations
{
    public class AlertConfiguration : IEntityTypeConfiguration<Alert>
    {
        public void Configure(EntityTypeBuilder<Alert> builder)
        {
            builder.ToTable("Alerts");

            builder.HasKey(a => a.Id);

            builder.Property(a => a.Acknowledged)
                .IsRequired();

            builder.Property(a => a.AcknowledgedBy)
                .HasMaxLength(100);

            builder.Property(a => a.CreatedAt)
                .IsRequired();

            builder.HasOne(a => a.ComplianceCheck)
                .WithMany()
                .HasForeignKey("ComplianceCheckId")
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasIndex(a => a.Acknowledged);
            builder.HasIndex("ComplianceCheckId");
        }
    }
}