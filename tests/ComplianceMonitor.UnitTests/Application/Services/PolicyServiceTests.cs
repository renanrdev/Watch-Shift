using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Application.Mapping;
using ComplianceMonitor.Application.Services;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using Moq;
using Xunit;

namespace ComplianceMonitor.UnitTests.Application.Services
{
    public class PolicyServiceTests
    {
        private readonly Mock<IPolicyRepository> _mockPolicyRepository;
        private readonly Mock<IPolicyEngine> _mockPolicyEngine;
        private readonly IMapper _mapper;
        private readonly PolicyService _policyService;

        public PolicyServiceTests()
        {
            _mockPolicyRepository = new Mock<IPolicyRepository>();
            _mockPolicyEngine = new Mock<IPolicyEngine>();

            // Configure AutoMapper
            var mapperConfig = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<MappingProfile>();
            });
            _mapper = mapperConfig.CreateMapper();

            _policyService = new PolicyService(_mockPolicyRepository.Object, _mockPolicyEngine.Object, _mapper);
        }

        [Fact]
        public async Task GetAllPoliciesAsync_ShouldReturnAllPolicies()
        {
            // Arrange
            var policies = new List<Policy>
            {
                new Policy("Policy1", "Description1", SeverityLevel.High, RuleType.Rbac),
                new Policy("Policy2", "Description2", SeverityLevel.Medium, RuleType.NetworkPolicy)
            };

            _mockPolicyRepository.Setup(r => r.GetAllAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(policies);

            // Act
            var result = await _policyService.GetAllPoliciesAsync();

            // Assert
            Assert.Equal(2, result.Count());
            Assert.Equal("Policy1", result.First().Name);
            Assert.Equal("Policy2", result.Last().Name);
        }

        [Fact]
        public async Task GetPolicyByIdAsync_WithValidId_ShouldReturnPolicy()
        {
            // Arrange
            var policyId = Guid.NewGuid();
            var policy = new Policy("Policy1", "Description1", SeverityLevel.High, RuleType.Rbac);

            _mockPolicyRepository.Setup(r => r.GetByIdAsync(policyId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(policy);

            // Act
            var result = await _policyService.GetPolicyByIdAsync(policyId);

            // Assert
            Assert.Equal(policy.Name, result.Name);
        }

        [Fact]
        public async Task GetPolicyByIdAsync_WithInvalidId_ShouldThrowKeyNotFoundException()
        {
            // Arrange
            var policyId = Guid.NewGuid();

            _mockPolicyRepository.Setup(r => r.GetByIdAsync(policyId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Policy)null);

            // Act & Assert
            await Assert.ThrowsAsync<KeyNotFoundException>(() =>
                _policyService.GetPolicyByIdAsync(policyId));
        }

        [Fact]
        public async Task CreatePolicyAsync_ShouldCreatePolicyWithEngine()
        {
            // Arrange
            var createDto = new PolicyCreateDto
            {
                Name = "New Policy",
                Description = "New Description",
                Severity = SeverityLevel.High,
                RuleType = RuleType.Rbac,
                RuleName = "cluster_admin"
            };

            var createdPolicy = new Policy(
                createDto.Name,
                createDto.Description,
                createDto.Severity,
                createDto.RuleType
            );

            _mockPolicyEngine.Setup(e => e.CreatePolicyAsync(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<SeverityLevel>(),
                    It.IsAny<RuleType>(),
                    It.IsAny<string>(),
                    It.IsAny<Dictionary<string, object>>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(createdPolicy);

            // Act
            var result = await _policyService.CreatePolicyAsync(createDto);

            // Assert
            Assert.Equal(createDto.Name, result.Name);
            Assert.Equal(createDto.Description, result.Description);

            _mockPolicyEngine.Verify(e => e.CreatePolicyAsync(
                createDto.Name,
                createDto.Description,
                createDto.Severity,
                createDto.RuleType,
                createDto.RuleName,
                It.IsAny<Dictionary<string, object>>(),
                It.IsAny<CancellationToken>()
            ), Times.Once);
        }
    }
}