using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Interfaces.Repositories;

namespace ComplianceMonitor.Application.Services
{
    public class PolicyService : IPolicyService
    {
        private readonly IPolicyRepository _policyRepository;
        private readonly IPolicyEngine _policyEngine;
        private readonly IMapper _mapper;

        public PolicyService(
            IPolicyRepository policyRepository,
            IPolicyEngine policyEngine,
            IMapper mapper)
        {
            _policyRepository = policyRepository ?? throw new ArgumentNullException(nameof(policyRepository));
            _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        }

        public async Task<IEnumerable<PolicyDto>> GetAllPoliciesAsync(bool? enabled = null, CancellationToken cancellationToken = default)
        {
            var policies = await _policyRepository.GetAllAsync(cancellationToken);

            if (enabled.HasValue)
            {
                policies = policies.Where(p => p.IsEnabled == enabled.Value);
            }

            return _mapper.Map<IEnumerable<PolicyDto>>(policies);
        }

        public async Task<PolicyDto> GetPolicyByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var policy = await _policyRepository.GetByIdAsync(id, cancellationToken);
            if (policy == null)
            {
                throw new KeyNotFoundException($"Policy with ID {id} not found");
            }

            return _mapper.Map<PolicyDto>(policy);
        }

        public async Task<PolicyDto> CreatePolicyAsync(PolicyCreateDto policyDto, CancellationToken cancellationToken = default)
        {
            // Adicionar o RuleName nos parâmetros
            var parameters = policyDto.Parameters ?? new Dictionary<string, object>();
            parameters["rule_name"] = policyDto.RuleName;

            var policy = await _policyEngine.CreatePolicyAsync(
                policyDto.Name,
                policyDto.Description,
                policyDto.Severity,
                policyDto.RuleType,
                policyDto.RuleName,
                parameters,
                cancellationToken);

            return _mapper.Map<PolicyDto>(policy);
        }

        public async Task<PolicyDto> UpdatePolicyAsync(Guid id, PolicyUpdateDto policyDto, CancellationToken cancellationToken = default)
        {
            var policy = await _policyRepository.GetByIdAsync(id, cancellationToken);
            if (policy == null)
            {
                throw new KeyNotFoundException($"Policy with ID {id} not found");
            }

            if (!string.IsNullOrWhiteSpace(policyDto.Name))
            {
                policy.UpdateName(policyDto.Name);
            }

            if (policyDto.Description != null)
            {
                policy.UpdateDescription(policyDto.Description);
            }

            if (policyDto.Severity.HasValue)
            {
                policy.UpdateSeverity(policyDto.Severity.Value);
            }

            if (policyDto.Parameters != null)
            {
                var ruleName = policy.Parameters.ContainsKey("rule_name") ? policy.Parameters["rule_name"] : null;
                var newParameters = policyDto.Parameters;
                if (ruleName != null)
                {
                    newParameters["rule_name"] = ruleName;
                }
                policy.UpdateParameters(newParameters);
            }

            if (policyDto.Enabled.HasValue)
            {
                if (policyDto.Enabled.Value)
                {
                    policy.Enable();
                }
                else
                {
                    policy.Disable();
                }
            }

            await _policyRepository.UpdateAsync(policy, cancellationToken);
            return _mapper.Map<PolicyDto>(policy);
        }

        public async Task DeletePolicyAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var policy = await _policyRepository.GetByIdAsync(id, cancellationToken);
            if (policy == null)
            {
                throw new KeyNotFoundException($"Policy with ID {id} not found");
            }

            await _policyRepository.DeleteAsync(id, cancellationToken);
        }
    }
}