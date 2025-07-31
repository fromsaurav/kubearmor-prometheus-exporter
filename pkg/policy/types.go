package policy

import (
	"sync"
)

type PolicyInfo struct {
	Name      string
	Namespace string
	Type      string
	Status    string
}

type PolicyCache struct {
	mu       sync.RWMutex
	policies map[string]*PolicyInfo
}

func NewPolicyCache() *PolicyCache {
	return &PolicyCache{
		policies: make(map[string]*PolicyInfo),
	}
}

func (pc *PolicyCache) AddPolicy(key string, policy *PolicyInfo) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.policies[key] = policy
}

func (pc *PolicyCache) RemovePolicy(key string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	delete(pc.policies, key)
}

func (pc *PolicyCache) GetPolicies() map[string]*PolicyInfo {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	
	result := make(map[string]*PolicyInfo)
	for k, v := range pc.policies {
		result[k] = v
	}
	return result
}

func (pc *PolicyCache) GetPolicy(key string) (*PolicyInfo, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	policy, exists := pc.policies[key]
	return policy, exists
}