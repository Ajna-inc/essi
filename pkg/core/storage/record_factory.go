package storage

import (
	"sync"
)

// RecordConstructor is a function that creates a new instance of a specific record type
type RecordConstructor func() Record

// recordRegistry holds all registered record constructors
var (
	recordRegistry = make(map[string]RecordConstructor)
	registryMutex  sync.RWMutex
)

// RegisterRecordType registers a record constructor for a given type name
func RegisterRecordType(typeName string, constructor RecordConstructor) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	recordRegistry[typeName] = constructor
}

// CreateRecord creates a new record instance of the specified type
func CreateRecord(typeName string) (Record, error) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	if constructor, exists := recordRegistry[typeName]; exists {
		return constructor(), nil
	}
	
	// Fallback to BaseRecord if type not registered
	// This maintains backward compatibility
	return NewBaseRecord(typeName), nil
}

// GetRegisteredTypes returns a list of all registered record types
func GetRegisteredTypes() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	types := make([]string, 0, len(recordRegistry))
	for typeName := range recordRegistry {
		types = append(types, typeName)
	}
	return types
}

// RecordTypeRegistered checks if a record type is registered
func RecordTypeRegistered(typeName string) bool {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	_, exists := recordRegistry[typeName]
	return exists
}