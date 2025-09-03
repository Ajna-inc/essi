package v2

import (
	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const (
	V2StatusRequestType    = "https://didcomm.org/messagepickup/2.0/status-request"
	V2StatusType           = "https://didcomm.org/messagepickup/2.0/status"
	V2DeliveryRequestType  = "https://didcomm.org/messagepickup/2.0/delivery-request"
	V2DeliveryType         = "https://didcomm.org/messagepickup/2.0/delivery"
	V2MessagesReceivedType = "https://didcomm.org/messagepickup/2.0/messages-received"
)

type V2StatusRequest struct {
	*base.BaseMessage
	RecipientKey string `json:"recipient_key,omitempty"`
}

func NewV2StatusRequest() *V2StatusRequest {
	return &V2StatusRequest{BaseMessage: base.NewBaseMessage(V2StatusRequestType)}
}

type V2DeliveryRequest struct {
	*base.BaseMessage
	RecipientKey string `json:"recipient_key,omitempty"`
	Limit        int    `json:"limit"`
}

func NewV2DeliveryRequest(limit int) *V2DeliveryRequest {
	m := &V2DeliveryRequest{BaseMessage: base.NewBaseMessage(V2DeliveryRequestType), Limit: limit}
	return m
}

// Generic attachment structure (subset)
type AttachmentData struct {
	Json   map[string]interface{} `json:"json,omitempty"`
	Base64 string                 `json:"base64,omitempty"`
}

type Attachment struct {
	Id   string         `json:"id"`
	Data AttachmentData `json:"data"`
}

type V2Delivery struct {
	*base.BaseMessage
	RecipientKey string       `json:"recipient_key,omitempty"`
	Attachments  []Attachment `json:"attachments"`
}

type V2MessagesReceived struct {
	*base.BaseMessage
	MessageIdList []string `json:"message_id_list"`
}

func NewV2MessagesReceived(ids []string) *V2MessagesReceived {
	return &V2MessagesReceived{BaseMessage: base.NewBaseMessage(V2MessagesReceivedType), MessageIdList: ids}
}











