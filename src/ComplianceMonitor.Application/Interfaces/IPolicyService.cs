using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;

namespace ComplianceMonitor.Application.Interfaces
{
    public interface IPolicyService
    {
        Task<IEnumerable<PolicyDto>> GetAllPoliciesAsync(bool? enabled = null, CancellationToken cancellationToken = default);
        Task<PolicyDto> GetPolicyByIdAsync(Guid id, CancellationToken cancellationToken = default);
        Task<PolicyDto> CreatePolicyAsync(PolicyCreateDto policyDto, CancellationToken cancellationToken = default);
        Task<PolicyDto> UpdatePolicyAsync(Guid id, PolicyUpdateDto policyDto, CancellationToken cancellationToken = default);
        Task DeletePolicyAsync(Guid id, CancellationToken cancellationToken = default);
    }
}