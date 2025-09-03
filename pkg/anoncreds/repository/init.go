package repository

import (
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// init registers all anoncreds record types with the storage system
func init() {
	// Register CredentialDefinitionRecord
	storage.RegisterRecordType("CredentialDefinitionRecord", func() storage.Record {
		return &CredentialDefinitionRecord{
			BaseRecord: storage.NewBaseRecord("CredentialDefinitionRecord"),
		}
	})

	// Register CredentialDefinitionPrivateRecord
	storage.RegisterRecordType("CredentialDefinitionPrivateRecord", func() storage.Record {
		return &CredentialDefinitionPrivateRecord{
			BaseRecord: storage.NewBaseRecord("CredentialDefinitionPrivateRecord"),
		}
	})

	// Register KeyCorrectnessProofRecord
	storage.RegisterRecordType("KeyCorrectnessProofRecord", func() storage.Record {
		return &KeyCorrectnessProofRecord{
			BaseRecord: storage.NewBaseRecord("KeyCorrectnessProofRecord"),
		}
	})
}