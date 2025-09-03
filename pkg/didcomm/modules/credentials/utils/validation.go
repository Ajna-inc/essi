package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
)

// CredentialValues represents the credential attribute values
type CredentialValues map[string]CredentialValue

// CredentialValue represents a single credential value with raw and encoded forms
type CredentialValue struct {
	Raw     string `json:"raw"`
	Encoded string `json:"encoded"`
}

// CredentialPreviewAttribute represents an attribute in the credential preview
type CredentialPreviewAttribute struct {
	Name     string `json:"name"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value"`
}

// ConvertAttributesToCredentialValues converts preview attributes to credential values
func ConvertAttributesToCredentialValues(attributes map[string]string) CredentialValues {
	values := make(CredentialValues)
	for name, value := range attributes {
		values[name] = CredentialValue{
			Raw:     value,
			Encoded: value, // For simplicity, using same value for encoded
		}
	}
	return values
}

// ConvertPreviewAttributesToCredentialValues converts preview attributes to credential values
func ConvertPreviewAttributesToCredentialValues(attributes []CredentialPreviewAttribute) CredentialValues {
	values := make(CredentialValues)
	for _, attr := range attributes {
		values[attr.Name] = CredentialValue{
			Raw:     attr.Value,
			Encoded: attr.Value, // For simplicity, using same value for encoded
		}
	}
	return values
}

// AssertCredentialValuesMatch validates that actual credential values match expected values
// This is critical for security - ensures the issuer provided the values we expected
func AssertCredentialValuesMatch(actual map[string]interface{}, expected CredentialValues) error {
	for expectedName, expectedValue := range expected {
		actualValueRaw, found := actual[expectedName]
		if !found {
			return fmt.Errorf("credential is missing expected attribute '%s'", expectedName)
		}
		
		// Handle the actual value which might be a map or a string
		var actualRaw, actualEncoded string
		switch v := actualValueRaw.(type) {
		case map[string]interface{}:
			if raw, ok := v["raw"].(string); ok {
				actualRaw = raw
			}
			if encoded, ok := v["encoded"].(string); ok {
				actualEncoded = encoded
			}
		case string:
			actualRaw = v
			actualEncoded = v
		default:
			return fmt.Errorf("invalid value type for attribute '%s'", expectedName)
		}
		
		if actualRaw != expectedValue.Raw {
			return fmt.Errorf("credential value mismatch for attribute '%s': expected '%s', got '%s'", 
				expectedName, expectedValue.Raw, actualRaw)
		}
		
		// If encoded is different from raw in expected, check it too
		if expectedValue.Encoded != expectedValue.Raw && actualEncoded != expectedValue.Encoded {
			return fmt.Errorf("credential encoded value mismatch for attribute '%s': expected '%s', got '%s'",
				expectedName, expectedValue.Encoded, actualEncoded)
		}
	}
	
	for actualName := range actual {
		if _, expected := expected[actualName]; !expected {
			return fmt.Errorf("credential contains unexpected attribute '%s'", actualName)
		}
	}
	
	return nil
}

// CheckCredentialValuesMatch checks if credential values match (non-throwing version)
func CheckCredentialValuesMatch(expected CredentialValues, actual map[string]interface{}) bool {
	err := AssertCredentialValuesMatch(actual, expected)
	return err == nil
}

// AssertAttributesMatch validates that preview attributes match schema attributes
func AssertAttributesMatch(schema map[string]interface{}, attributes []CredentialPreviewAttribute) error {
	// Extract attribute names from schema
	var schemaAttrSet map[string]bool
	schemaAttrSet = make(map[string]bool)
	
	// Try different types for attrNames
	if attrNames := schema["attrNames"]; attrNames != nil {
		switch attrs := attrNames.(type) {
		case []string:
			for _, attr := range attrs {
				schemaAttrSet[attr] = true
			}
		case []interface{}:
			for _, attr := range attrs {
				if attrStr, ok := attr.(string); ok {
					schemaAttrSet[attrStr] = true
				}
			}
		default:
			// Try alternative schema formats
			if attrs, ok := schema["attributes"].([]interface{}); ok {
				for _, attr := range attrs {
					if attrStr, ok := attr.(string); ok {
						schemaAttrSet[attrStr] = true
					}
				}
			} else if attrs, ok := schema["attribute_names"].([]interface{}); ok {
				for _, attr := range attrs {
					if attrStr, ok := attr.(string); ok {
						schemaAttrSet[attrStr] = true
					}
				}
			} else {
				return fmt.Errorf("unable to extract attribute names from schema")
			}
		}
	} else {
		return fmt.Errorf("unable to extract attribute names from schema")
	}
	
	for _, attr := range attributes {
		if !schemaAttrSet[attr.Name] {
			validAttrs := make([]string, 0, len(schemaAttrSet))
			for name := range schemaAttrSet {
				validAttrs = append(validAttrs, name)
			}
			sort.Strings(validAttrs)
			return fmt.Errorf("attribute '%s' is not present in schema. Valid attributes are: %s",
				attr.Name, strings.Join(validAttrs, ", "))
		}
	}
	
	for schemaAttr := range schemaAttrSet {
		found := false
		for _, attr := range attributes {
			if attr.Name == schemaAttr {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("required schema attribute '%s' is missing from preview", schemaAttr)
		}
	}
	
	return nil
}

// AssertAttributesMatchMap validates that preview attributes match schema attributes (map version)
func AssertAttributesMatchMap(schema map[string]interface{}, attributes map[string]string) error {
	// Debug: log schema structure
	if schemaJSON, err := json.Marshal(schema); err == nil {
		log.Printf("🔍 Schema structure for validation: %s", string(schemaJSON))
	}
	
	// Convert map to slice of preview attributes
	previewAttrs := make([]CredentialPreviewAttribute, 0, len(attributes))
	for name, value := range attributes {
		previewAttrs = append(previewAttrs, CredentialPreviewAttribute{
			Name:  name,
			Value: value,
		})
	}
	return AssertAttributesMatch(schema, previewAttrs)
}