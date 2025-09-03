package anoncreds

import (
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credutils "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/utils"
)

// AddOfferFormat annotates offer with anoncreds format and payload
func AddOfferFormat(offer *credmsgs.OfferCredentialV2, attachID string, payload map[string]interface{}) {
	offer.Formats = append(offer.Formats, credmsgs.FormatEntry{AttachID: attachID, Format: FormatOffer})
	offer.OffersAttach = append(offer.OffersAttach, credutils.BuildAttachmentJSON(attachID, payload))
}

// BuildRequestWithAnonCreds builds a request message with anoncreds request payload
func BuildRequestWithAnonCreds(thid string, payload map[string]interface{}) *credmsgs.RequestCredentialV2 {
	req := credmsgs.NewRequestCredentialV2()
	req.SetThreadId(thid)
	req.Formats = append(req.Formats, credmsgs.FormatEntry{AttachID: "req-0", Format: FormatRequest})
	req.RequestsAttach = append(req.RequestsAttach, credutils.BuildAttachmentJSON("req-0", payload))
	return req
}

// BuildIssuedWithAnonCreds builds an issued credential message with anoncreds payload
func BuildIssuedWithAnonCreds(thid string, payload map[string]interface{}) *credmsgs.IssueCredentialV2Credential {
	cred := credmsgs.NewIssueCredentialV2Credential()
	cred.SetThreadId(thid)
	cred.Formats = append(cred.Formats, credmsgs.FormatEntry{AttachID: "cred-0", Format: FormatCredential})
	cred.CredentialsAttach = append(cred.CredentialsAttach, credutils.BuildAttachmentJSON("cred-0", payload))
	return cred
}
