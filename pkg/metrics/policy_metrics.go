package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	KubeArmorPoliciesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_total",
			Help: "Total number of KubeArmor policies by type",
		}, []string{"type"})

	KubeArmorPolicyInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policy_info",
			Help: "Information about KubeArmor policies",
		}, []string{"name", "namespace", "type", "status"})

	KubeArmorPoliciesByNamespaceTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_by_namespace_total",
			Help: "Total number of KubeArmor policies by namespace and type",
		}, []string{"namespace", "type"})
)

func RegisterPolicyMetrics() {
	prometheus.MustRegister(KubeArmorPoliciesTotal)
	prometheus.MustRegister(KubeArmorPolicyInfo)
	prometheus.MustRegister(KubeArmorPoliciesByNamespaceTotal)
}

func ResetPolicyMetrics() {
	KubeArmorPoliciesTotal.Reset()
	KubeArmorPolicyInfo.Reset()
	KubeArmorPoliciesByNamespaceTotal.Reset()
}