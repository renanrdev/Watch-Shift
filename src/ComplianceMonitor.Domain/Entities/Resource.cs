using System;
using System.Collections.Generic;

namespace ComplianceMonitor.Domain.Entities
{
    public class KubernetesResource
    {
        public Guid Id { get; private set; }
        public string Kind { get; private set; }
        public string Name { get; private set; }
        public string Namespace { get; private set; }
        public string Uid { get; private set; }
        public Dictionary<string, string> Labels { get; private set; }
        public Dictionary<string, string> Annotations { get; private set; }
        public Dictionary<string, object> Spec { get; private set; }
        public DateTime CreatedAt { get; private set; }

        private KubernetesResource() { }

        public KubernetesResource(
            string kind,
            string name,
            string @namespace,
            string uid,
            Dictionary<string, string> labels = null,
            Dictionary<string, string> annotations = null,
            Dictionary<string, object> spec = null)
        {
            Id = Guid.NewGuid();
            Kind = kind;
            Name = name;
            Namespace = @namespace;
            Uid = uid;
            Labels = labels ?? new Dictionary<string, string>();
            Annotations = annotations ?? new Dictionary<string, string>();
            Spec = spec ?? new Dictionary<string, object>();
            CreatedAt = DateTime.UtcNow;
        }
    }
}