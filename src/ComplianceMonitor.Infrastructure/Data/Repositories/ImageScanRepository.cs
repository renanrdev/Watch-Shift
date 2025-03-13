using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace ComplianceMonitor.Infrastructure.Data.Repositories
{
    public class ImageScanRepository : IImageScanRepository
    {
        private readonly ComplianceDbContext _context;
        private readonly ILogger<ImageScanRepository>  _logger;
        

        public ImageScanRepository(ComplianceDbContext context, ILogger<ImageScanRepository> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task AddAsync(ImageScanResult scanResult, CancellationToken cancellationToken = default)
        {
            try
            {
                // Criar um conjunto com IDs de vulnerabilidades para verificar duplicatas
                var vulnerabilityIds = new HashSet<string>();
                var duplicateVulnerabilities = new List<Vulnerability>();

                // Verificar vulnerabilidades duplicadas dentro do próprio resultado
                foreach (var vulnerability in scanResult.Vulnerabilities.ToList())
                {
                    if (!vulnerabilityIds.Add(vulnerability.Id.ToString()))
                    {
                        // Encontrou uma duplicata dentro do próprio resultado
                        duplicateVulnerabilities.Add(vulnerability);
                        scanResult.Vulnerabilities.Remove(vulnerability);
                    }
                }

                if (duplicateVulnerabilities.Any())
                {
                    _logger.LogWarning($"Removed {duplicateVulnerabilities.Count} duplicate vulnerabilities from scan result");
                }

                // Verificar primeiro se já existe um resultado para esta imagem
                var existingResult = await _context.ImageScans
                    .FirstOrDefaultAsync(s => s.ImageName == scanResult.ImageName, cancellationToken);

                if (existingResult != null)
                {
                    // Excluir o resultado existente para evitar conflitos
                    _context.ImageScans.Remove(existingResult);
                    await _context.SaveChangesAsync(cancellationToken);
                    _logger.LogInformation($"Removed previous scan result for {scanResult.ImageName}");
                }

                // Definir o ID para cada vulnerabilidade manualmente para garantir que seja único
                foreach (var vulnerability in scanResult.Vulnerabilities)
                {
                    vulnerability.SetImageScanResultId(scanResult.Id);
                }

                // Adicionar o novo resultado
                await _context.ImageScans.AddAsync(scanResult, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving scan result for {scanResult.ImageName}");
                throw;
            }
        }

        public async Task<ImageScanResult> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
        }

        public async Task<IEnumerable<ImageScanResult>> GetByImageNameAsync(string imageName, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .Where(s => s.ImageName == imageName)
                .OrderByDescending(s => s.ScanTime)
                .ToListAsync(cancellationToken);
        }

        public async Task<ImageScanResult> GetLatestByImageNameAsync(string imageName, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .Where(s => s.ImageName == imageName)
                .OrderByDescending(s => s.ScanTime)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public async Task<IEnumerable<ImageScanResult>> GetAllAsync(int limit = 100, int offset = 0, CancellationToken cancellationToken = default)
        {
            return await _context.ImageScans
                .Include(s => s.Vulnerabilities)
                .OrderByDescending(s => s.ScanTime)
                .Skip(offset)
                .Take(limit)
                .ToListAsync(cancellationToken);
        }
    }
}