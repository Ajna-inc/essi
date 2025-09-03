package utils

import (
	didmsg "github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// FindAttachmentById returns first attachment with given id
func FindAttachmentById(atts []didmsg.AttachmentDecorator, id string) *didmsg.AttachmentDecorator {
	for i := range atts {
		if atts[i].Id == id {
			return &atts[i]
		}
	}
	return nil
}

// BuildAttachmentJSON creates a JSON attachment with id and payload
func BuildAttachmentJSON(id string, payload map[string]interface{}) didmsg.AttachmentDecorator {
	return didmsg.AttachmentDecorator{
		Id:   id,
		Data: &didmsg.AttachmentData{Json: payload},
	}
}
