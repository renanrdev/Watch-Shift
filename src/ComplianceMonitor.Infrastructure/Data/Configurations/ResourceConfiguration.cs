using ComplianceMonitor.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ComplianceMonitor.Infrastructure.Data.Configurations
{
    public class ResourceConfiguration : IEntityTypeConfiguration<KubernetesResource>
    {
        public void Configure(EntityTypeBuilder<KubernetesResource> builder)
        {
            builder.ToTable("Resources");

            builder.HasKey(r => r.Id);

            builder.Property(r => r.Kind)
                .IsRequired()
                .HasMaxLength(100);

            builder.Property(r => r.Name)
                .IsRequired()
                .HasMaxLength(253); 

            builder.Property(r => r.Namespace)
                .HasMaxLength(253);

            builder.Property(r => r.Uid)
                .IsRequired()
                .HasMaxLength(36);

            builder.Property(r => r.CreatedAt)
                .IsRequired();

            builder.HasMany<ComplianceCheck>()
                .WithOne(c => c.Resource)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasIndex(r => r.Uid).IsUnique();
            builder.HasIndex(r => r.Kind);
            builder.HasIndex(r => r.Namespace);
        }
    }
}