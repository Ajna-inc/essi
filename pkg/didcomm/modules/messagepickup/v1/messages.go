package v1

import (
	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
	envsvc "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// V1BatchPickup https://didcomm.org/messagepickup/1.0/batch-pickup
const V1BatchPickupType = "https://didcomm.org/messagepickup/1.0/batch-pickup"

type V1BatchPickup struct {
	*base.BaseMessage
	BatchSize int `json:"batch_size"`
}

func NewV1BatchPickup(batchSize int) *V1BatchPickup {
	m := &V1BatchPickup{BaseMessage: base.NewBaseMessage(V1BatchPickupType), BatchSize: batchSize}
	return m
}

// V1Batch https://didcomm.org/messagepickup/1.0/batch
const V1BatchType = "https://didcomm.org/messagepickup/1.0/batch"

type V1BatchAttachment struct {
	Id      string                   `json:"id"`
	Message *envsvc.EncryptedMessage `json:"message"`
}

type V1Batch struct {
	*base.BaseMessage
	Messages []V1BatchAttachment `json:"messages~attach"`
}











