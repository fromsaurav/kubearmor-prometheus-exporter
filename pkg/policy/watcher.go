package policy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kubearmor/kubearmor-prometheus-exporter/pkg/metrics"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type PolicyWatcher struct {
	clientset     kubernetes.Interface
	dynamicClient dynamic.Interface
	cache         *PolicyCache
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

func NewPolicyWatcher(clientset kubernetes.Interface, dynamicClient dynamic.Interface) *PolicyWatcher {
	return &PolicyWatcher{
		clientset:     clientset,
		dynamicClient: dynamicClient,
		cache:         NewPolicyCache(),
		stopCh:        make(chan struct{}),
	}
}

func (pw *PolicyWatcher) Start() error {
	log.Println("Starting KubeArmor policy watcher...")

	crds := []struct {
		group    string
		version  string
		resource string
		kind     string
	}{
		{"security.kubearmor.com", "v1", "kubearmorpolicies", "KubeArmorPolicy"},
		{"security.kubearmor.com", "v1", "kubearmorhostpolicies", "KubeArmorHostPolicy"},
		{"security.kubearmor.com", "v1", "kubearmorclusterpolicies", "KubeArmorClusterPolicy"},
	}

	for _, crd := range crds {
		pw.wg.Add(1)
		go pw.watchCRD(crd.group, crd.version, crd.resource, crd.kind)
	}

	pw.wg.Add(1)
	go pw.metricsUpdater()

	return nil
}

func (pw *PolicyWatcher) Stop() {
	log.Println("Stopping KubeArmor policy watcher...")
	close(pw.stopCh)
	pw.wg.Wait()
}

func (pw *PolicyWatcher) watchCRD(group, version, resource, kind string) {
	defer pw.wg.Done()

	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}

	for {
		select {
		case <-pw.stopCh:
			return
		default:
		}

		watcher, err := pw.dynamicClient.Resource(gvr).Watch(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Failed to watch %s: %v", kind, err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range watcher.ResultChan() {
			if event.Type == watch.Error {
				log.Printf("Watch error for %s: %v", kind, event.Object)
				break
			}

			unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}

			policy := pw.convertToPolicy(unstructuredObj, kind)
			key := fmt.Sprintf("%s/%s/%s", policy.Type, policy.Namespace, policy.Name)

			switch event.Type {
			case watch.Added, watch.Modified:
				pw.cache.AddPolicy(key, policy)
				log.Printf("Policy %s %s: %s", event.Type, kind, key)
			case watch.Deleted:
				pw.cache.RemovePolicy(key)
				log.Printf("Policy deleted: %s", key)
			}
		}

		watcher.Stop()
		time.Sleep(1 * time.Second)
	}
}

func (pw *PolicyWatcher) convertToPolicy(obj *unstructured.Unstructured, kind string) *PolicyInfo {
	name := obj.GetName()
	namespace := obj.GetNamespace()
	
	if namespace == "" && kind != "KubeArmorClusterPolicy" {
		namespace = "default"
	}

	status := "active"
	if statusField, found, err := unstructured.NestedString(obj.Object, "status", "phase"); found && err == nil {
		if statusField == "inactive" || statusField == "disabled" {
			status = "inactive"
		}
	}

	return &PolicyInfo{
		Name:      name,
		Namespace: namespace,
		Type:      kind,
		Status:    status,
	}
}

func (pw *PolicyWatcher) metricsUpdater() {
	defer pw.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pw.stopCh:
			return
		case <-ticker.C:
			pw.updateMetrics()
		}
	}
}

func (pw *PolicyWatcher) updateMetrics() {
	policies := pw.cache.GetPolicies()

	metrics.ResetPolicyMetrics()

	typeCounts := make(map[string]float64)
	namespaceCounts := make(map[string]map[string]float64)

	for _, policy := range policies {
		typeCounts[policy.Type]++

		if namespaceCounts[policy.Namespace] == nil {
			namespaceCounts[policy.Namespace] = make(map[string]float64)
		}
		namespaceCounts[policy.Namespace][policy.Type]++

		metrics.KubeArmorPolicyInfo.WithLabelValues(
			policy.Name,
			policy.Namespace,
			policy.Type,
			policy.Status,
		).Set(1)
	}

	for policyType, count := range typeCounts {
		metrics.KubeArmorPoliciesTotal.WithLabelValues(policyType).Set(count)
	}

	for namespace, typeMap := range namespaceCounts {
		for policyType, count := range typeMap {
			metrics.KubeArmorPoliciesByNamespaceTotal.WithLabelValues(namespace, policyType).Set(count)
		}
	}
}