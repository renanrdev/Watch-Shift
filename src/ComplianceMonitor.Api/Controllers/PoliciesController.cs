using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.DTOs;
using ComplianceMonitor.Application.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ComplianceMonitor.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PoliciesController : ControllerBase
    {
        private readonly IPolicyService _policyService;

        public PoliciesController(IPolicyService policyService)
        {
            _policyService = policyService ?? throw new ArgumentNullException(nameof(policyService));
        }

        [HttpGet]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<PolicyDto>>> GetPolicies([FromQuery] bool? enabled = null, CancellationToken cancellationToken = default)
        {
            var policies = await _policyService.GetAllPoliciesAsync(enabled, cancellationToken);
            return Ok(policies);
        }

        [HttpGet("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<PolicyDto>> GetPolicy(Guid id, CancellationToken cancellationToken = default)
        {
            var policy = await _policyService.GetPolicyByIdAsync(id, cancellationToken);
            return Ok(policy);
        }

        [HttpPost]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<PolicyDto>> CreatePolicy(PolicyCreateDto policyDto, CancellationToken cancellationToken = default)
        {
            var createdPolicy = await _policyService.CreatePolicyAsync(policyDto, cancellationToken);
            return CreatedAtAction(nameof(GetPolicy), new { id = createdPolicy.Id }, createdPolicy);
        }

        [HttpPut("{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<PolicyDto>> UpdatePolicy(Guid id, PolicyUpdateDto policyDto, CancellationToken cancellationToken = default)
        {
            var updatedPolicy = await _policyService.UpdatePolicyAsync(id, policyDto, cancellationToken);
            return Ok(updatedPolicy);
        }

        [HttpDelete("{id}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> DeletePolicy(Guid id, CancellationToken cancellationToken = default)
        {
            await _policyService.DeletePolicyAsync(id, cancellationToken);
            return NoContent();
        }
    }
}
