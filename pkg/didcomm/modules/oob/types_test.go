package oob

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutOfBandStates(t *testing.T) {
	// Test that all Credo-TS states are defined
	assert.Equal(t, "initial", OutOfBandStateInitial)
	assert.Equal(t, "await-response", OutOfBandStateAwaitResponse)
	assert.Equal(t, "prepare-response", OutOfBandStatePrepareResponse)
	assert.Equal(t, "done", OutOfBandStateDone)
}

func TestOutOfBandRoles(t *testing.T) {
	// Test that roles match Credo-TS
	assert.Equal(t, OutOfBandRole("sender"), OutOfBandRoleSender)
	assert.Equal(t, OutOfBandRole("receiver"), OutOfBandRoleReceiver)
}

func TestOutOfBandRecord_AssertRole(t *testing.T) {
	tests := []struct {
		name         string
		recordRole   OutOfBandRole
		expectedRole OutOfBandRole
		wantErr      bool
		errorMsg     string
	}{
		{
			name:         "Valid sender role",
			recordRole:   OutOfBandRoleSender,
			expectedRole: OutOfBandRoleSender,
			wantErr:      false,
		},
		{
			name:         "Valid receiver role",
			recordRole:   OutOfBandRoleReceiver,
			expectedRole: OutOfBandRoleReceiver,
			wantErr:      false,
		},
		{
			name:         "Invalid role - expected sender got receiver",
			recordRole:   OutOfBandRoleReceiver,
			expectedRole: OutOfBandRoleSender,
			wantErr:      true,
			errorMsg:     "invalid out-of-band record role receiver, expected is sender",
		},
		{
			name:         "Invalid role - expected receiver got sender",
			recordRole:   OutOfBandRoleSender,
			expectedRole: OutOfBandRoleReceiver,
			wantErr:      true,
			errorMsg:     "invalid out-of-band record role sender, expected is receiver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &OutOfBandRecord{
				Role: tt.recordRole,
			}

			err := record.AssertRole(tt.expectedRole)

			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errorMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOutOfBandRecord_AssertState(t *testing.T) {
	tests := []struct {
		name           string
		recordState    string
		expectedStates []string
		wantErr        bool
		errorMsg       string
	}{
		{
			name:           "Valid single state",
			recordState:    OutOfBandStateInitial,
			expectedStates: []string{OutOfBandStateInitial},
			wantErr:        false,
		},
		{
			name:           "Valid state in multiple options",
			recordState:    OutOfBandStatePrepareResponse,
			expectedStates: []string{OutOfBandStateInitial, OutOfBandStatePrepareResponse},
			wantErr:        false,
		},
		{
			name:           "Invalid state",
			recordState:    OutOfBandStateDone,
			expectedStates: []string{OutOfBandStateInitial, OutOfBandStatePrepareResponse},
			wantErr:        true,
			errorMsg:       "invalid out-of-band record state done, valid states are: initial, prepare-response",
		},
		{
			name:           "No expected states provided",
			recordState:    OutOfBandStateInitial,
			expectedStates: []string{},
			wantErr:        true,
			errorMsg:       "no expected states provided",
		},
		{
			name:           "State matches one of many",
			recordState:    OutOfBandStateAwaitResponse,
			expectedStates: []string{OutOfBandStateInitial, OutOfBandStateAwaitResponse, OutOfBandStateDone},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &OutOfBandRecord{
				State: tt.recordState,
			}

			err := record.AssertState(tt.expectedStates...)

			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errorMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOutOfBandRecord_ReuseConnectionId(t *testing.T) {
	// Test that ReuseConnectionId field exists and works correctly
	record := &OutOfBandRecord{
		BaseRecord:        storage.NewBaseRecord("OutOfBandRecord"),
		ID:                "test-id",
		Role:              OutOfBandRoleReceiver,
		State:             OutOfBandStateInitial,
		ReuseConnectionId: "connection-123", // This field should exist
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	assert.Equal(t, "connection-123", record.ReuseConnectionId)

	// Test JSON serialization includes the field
	data, err := record.ToJSON()
	require.NoError(t, err)
	assert.Contains(t, string(data), "reuseConnectionId")
	assert.Contains(t, string(data), "connection-123")

	// Test JSON deserialization preserves the field
	newRecord := &OutOfBandRecord{
		BaseRecord: storage.NewBaseRecord("OutOfBandRecord"),
	}
	err = newRecord.FromJSON(data)
	require.NoError(t, err)
	assert.Equal(t, "connection-123", newRecord.ReuseConnectionId)
}

func TestOutOfBandRecord_Metadata(t *testing.T) {
	record := &OutOfBandRecord{
		BaseRecord: storage.NewBaseRecord("OutOfBandRecord"),
	}

	// Test setting metadata
	record.SetMetadata("testKey", "testValue")
	value := record.GetMetadata("testKey")
	assert.Equal(t, "testValue", value)

	// Test getting non-existent metadata
	value = record.GetMetadata("nonExistent")
	assert.Nil(t, value)

	// Test complex metadata
	complexData := map[string]interface{}{
		"nested": "value",
		"number": 42,
	}
	record.SetMetadata("complex", complexData)
	retrieved := record.GetMetadata("complex")
	assert.Equal(t, complexData, retrieved)
}

func TestStateTransitions(t *testing.T) {
	// Test valid state transitions matching Credo-TS
	tests := []struct {
		name        string
		role        OutOfBandRole
		fromState   string
		toState     string
		valid       bool
		description string
	}{
		// Receiver transitions
		{
			name:        "Receiver: Initial to PrepareResponse",
			role:        OutOfBandRoleReceiver,
			fromState:   OutOfBandStateInitial,
			toState:     OutOfBandStatePrepareResponse,
			valid:       true,
			description: "Receiver accepts invitation",
		},
		{
			name:        "Receiver: PrepareResponse to Done",
			role:        OutOfBandRoleReceiver,
			fromState:   OutOfBandStatePrepareResponse,
			toState:     OutOfBandStateDone,
			valid:       true,
			description: "Receiver completes exchange",
		},
		// Sender transitions
		{
			name:        "Sender: AwaitResponse to Done",
			role:        OutOfBandRoleSender,
			fromState:   OutOfBandStateAwaitResponse,
			toState:     OutOfBandStateDone,
			valid:       true,
			description: "Sender receives response",
		},
		// Invalid transitions
		{
			name:        "Invalid: Initial to Done",
			role:        OutOfBandRoleReceiver,
			fromState:   OutOfBandStateInitial,
			toState:     OutOfBandStateDone,
			valid:       false,
			description: "Cannot skip PrepareResponse",
		},
		{
			name:        "Invalid: Done to any state",
			role:        OutOfBandRoleSender,
			fromState:   OutOfBandStateDone,
			toState:     OutOfBandStateAwaitResponse,
			valid:       false,
			description: "Done is terminal state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test documents expected transitions
			// Actual validation would be in the service layer
			t.Logf("Role: %s, Transition: %s -> %s (%s): %v",
				tt.role, tt.fromState, tt.toState, tt.description, tt.valid)
		})
	}
}
