package resolve

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
)

// RegistryResolver adapts the pluggable registry.Service to the
// anoncreds.Resolver interface expected by the credential flow.
// It converts typed models into JSON-compatible maps matching
// anoncreds-rs expectations.
type RegistryResolver struct {
	svc *registry.Service
}

func NewRegistryResolver(svc *registry.Service) *RegistryResolver {
	return &RegistryResolver{svc: svc}
}

// ResolveCredentialDefinition returns a JSON-compatible map of the credential definition
// with structure matching anoncreds-rs expectations:
//
//	{
//	  issuerId, schemaId, type: "CL", tag,
//	  value: { primary: { value: { ...cl fields... } } }
//	}
func (r *RegistryResolver) ResolveCredentialDefinition(credDefId string) (map[string]interface{}, error) {
	if r == nil || r.svc == nil {
		return nil, fmt.Errorf("resolver not initialized")
	}
	cd, _, err := r.svc.GetCredentialDefinition(credDefId)
	if err != nil {
		return nil, err
	}
	// Normalize credential definition value structure to match anoncreds-rs expectations.
	// - If primary has nested .value, flatten it.
	// - Ensure big-number fields are plain strings (not wrapped) for credx JSON compatibility.
	value := cd.Value
	if value == nil {
		value = map[string]interface{}{}
	}
	if primaryRaw, ok := value["primary"]; ok {
		if primaryMap, ok := primaryRaw.(map[string]interface{}); ok {
			// If nested under primary.value, flatten it
			if inner, ok := primaryMap["value"].(map[string]interface{}); ok {
				primaryMap = inner
			}
			// Ensure numbers are strings, not wrapped objects
			for k, v := range primaryMap {
				switch t := v.(type) {
				case map[string]interface{}:
					// Unwrap { value: string } to string for fields and for 'r' entries
					if val, ok := t["value"].(string); ok {
						primaryMap[k] = val
						continue
					}
					for rk, rv := range t {
						if rvm, ok := rv.(map[string]interface{}); ok {
							if val, ok := rvm["value"].(string); ok {
								t[rk] = val
							}
						}
					}
					primaryMap[k] = t
				}
			}
			value["primary"] = primaryMap
		}
	}
	return map[string]interface{}{
		"issuerId": cd.IssuerId,
		"schemaId": cd.SchemaId,
		"type":     "CL",
		"tag":      cd.Tag,
		"value":    value,
	}, nil
}

// ResolveSchema returns a JSON-compatible map of the schema
//
//	{
//	  attrNames: [], name, version, issuerId
//	}
func (r *RegistryResolver) ResolveSchema(schemaId string) (map[string]interface{}, error) {
	if r == nil || r.svc == nil {
		return nil, fmt.Errorf("resolver not initialized")
	}
	s, _, err := r.svc.GetSchema(schemaId)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"attrNames": s.AttrNames,
		"name":      s.Name,
		"version":   s.Version,
		"issuerId":  s.IssuerId,
	}, nil
}
