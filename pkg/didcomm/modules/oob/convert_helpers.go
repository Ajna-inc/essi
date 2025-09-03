package oob

import (
	conmsg "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	messages_oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
)

// ConvertToNewInvitation converts a legacy Connections invitation to an OOB invitation.
// Replacement for the removed converters.go function, delegating to messages package helper.
func ConvertToNewInvitation(connInvitation *conmsg.ConnectionInvitationMessage) (*messages_oob.OutOfBandInvitationMessage, error) {
	return messages_oob.FromConnectionInvitation(connInvitation)
}
