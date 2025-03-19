using System.Linq;
using AutoMapper;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;

namespace ComplianceMonitor.Application.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Policy, PolicyDto>()
                .ForMember(dest => dest.Enabled, opt => opt.MapFrom(src => src.IsEnabled));

            CreateMap<Vulnerability, VulnerabilityDto>();

            CreateMap<ImageScanResult, ImageScanResultDto>()
                .ForMember(dest => dest.SeverityCounts, opt => opt.MapFrom(src =>
                    src.CountBySeverity().ToDictionary(
                        kvp => kvp.Key.ToString(),
                        kvp => kvp.Value)));
        }
    }
}
