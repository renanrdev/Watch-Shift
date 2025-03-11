using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ComplianceMonitor.Application.Interfaces;
using ComplianceMonitor.Domain.Entities;
using ComplianceMonitor.Domain.Enums;
using ComplianceMonitor.Domain.Interfaces.Repositories;
using ComplianceMonitor.Domain.Interfaces.Services;
using ComplianceMonitor.Domain.Specifications.Rules.Network;
using ComplianceMonitor.Domain.Specifications.Rules.RBAC;
using ComplianceMonitor.Domain.Specifications.Rules.SCC;
using Microsoft.Extensions.Logging;

namespace ComplianceMonitor.Application.Services
{
    public class PolicyEngine : IPolicyEngine
    {
        private readonly IPolicyRepository _policyRepository;
        private readonly ILogger<PolicyEngine> _logger;
        private readonly Dictionary<RuleType, Dictionary<string, Type>> _ruleTypes;

        public PolicyEngine(
            IPolicyRepository policyRepository,
            ILogger<PolicyEngine> logger)
        {
            _policyRepository = policyRepository ?? throw new ArgumentNullException(nameof(policyRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Register rule types
            _ruleTypes = new Dictionary<RuleType, Dictionary<string, Type>>
            {
                [RuleType.Rbac] = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
                {
                    ["cluster_admin"] = typeof(ClusterAdminRBACRule),
                    ["wildcard_permissions"] = typeof(WildcardPermissionsRBACRule)
                },
                [RuleType.SecurityContextConstraint] = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
                {
                    ["privileged_containers"] = typeof(PrivilegedContainersSCCRule)
                },
                [RuleType.NetworkPolicy] = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
                {
                    ["default_deny"] = typeof(DefaultDenyNetworkPolicyRule)
                }
            };
        }

        public async Task<Policy> CreatePolicyAsync(
            string name,
            string description,
            SeverityLevel severity,
            RuleType ruleType,
            string ruleName,
            Dictionary<string, object> parameters = null,
            CancellationToken cancellationToken = default)
        {
            // Validate rule type and name
            if (!_ruleTypes.TryGetValue(ruleType, out var ruleTypeDict))
            {
                throw new ArgumentException($"Unsupported rule type: {ruleType}");
            }

            if (!ruleTypeDict.ContainsKey(ruleName))
            {
                throw new ArgumentException($"Unsupported rule name for {ruleType}: {ruleName}");
            }

            // Prepare parameters
            var allParameters = parameters ?? new Dictionary<string, object>();
            allParameters["rule_name"] = ruleName;

            // Create policy
            var policy = new Policy(
                name: name,
                description: description,
                severity: severity,
                ruleType: ruleType,
                parameters: allParameters
            );

            await _policyRepository.AddAsync(policy, cancellationToken);
            return policy;
        }

        public async Task<IEnumerable<Policy>> GetAllPoliciesAsync(CancellationToken cancellationToken = default)
        {
            return await _policyRepository.GetAllAsync(cancellationToken);
        }

        public async Task<Policy> GetPolicyAsync(Guid policyId, CancellationToken cancellationToken = default)
        {
            return await _policyRepository.GetByIdAsync(policyId, cancellationToken);
        }

        public async Task<ComplianceCheck> EvaluatePolicyAsync(
            Policy policy,
            KubernetesResource resource,
            CancellationToken cancellationToken = default)
        {
            var rule = CreateRuleForPolicy(policy);

            // Check if rule applies to resource
            if (!rule.AppliesTo(resource))
            {
                return new ComplianceCheck(
                    policy: policy,
                    resource: resource,
                    status: ComplianceStatus.Unknown,
                    details: new Dictionary<string, object>
                    {
                        ["message"] = $"Rule does not apply to resource type {resource.Kind}"
                    }
                );
            }

            // Evaluate resource
            var status = rule.Evaluate(resource);
            var details = new Dictionary<string, object>(rule.GetDetails())
            {
                ["resource_kind"] = resource.Kind,
                ["resource_name"] = resource.Name,
                ["resource_namespace"] = resource.Namespace
            };

            return new ComplianceCheck(
                policy: policy,
                resource: resource,
                status: status,
                details: details
            );
        }

        private IPolicyRule CreateRuleForPolicy(Policy policy)
        {
            // Get rule name from parameters
            if (!policy.Parameters.TryGetValue("rule_name", out var ruleNameObj) ||
                ruleNameObj is not string ruleName)
            {
                throw new InvalidOperationException($"Policy {policy.Name} does not specify a rule_name");
            }

            // Validate rule type and name
            if (!_ruleTypes.TryGetValue(policy.RuleType, out var ruleTypeDict))
            {
                throw new InvalidOperationException($"Unsupported rule type: {policy.RuleType}");
            }

            if (!ruleTypeDict.TryGetValue(ruleName, out var ruleType))
            {
                throw new InvalidOperationException($"Unsupported rule name {ruleName} for type {policy.RuleType}");
            }

            // Create rule instance
            try
            {
                // For simplicity, we're using parameterless constructors for rules
                // In a real implementation, you might want to use a more sophisticated approach to handle
                // rule parameters and dependencies
                return (IPolicyRule)Activator.CreateInstance(ruleType);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to create rule instance for {ruleName}: {ex.Message}", ex);
            }
        }
    }
}