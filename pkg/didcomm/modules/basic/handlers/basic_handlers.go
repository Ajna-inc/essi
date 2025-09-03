package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// BasicMessageType is the type for basic messages
const BasicMessageType = "https://didcomm.org/basicmessage/1.0/message"

// ProblemReportType is the type for problem reports
const ProblemReportType = "https://didcomm.org/notification/1.0/problem-report"

// BasicMessageHandlerFunc handles basic messages
func BasicMessageHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var msg BasicMessage
	if err := json.Unmarshal(ctx.Raw, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse basic message: %w", err)
	}
	logger.GetDefaultLogger().Infof("💬 BasicMessage received: %s (sent_time=%s)", msg.Content, msg.SentTime)
	return nil, nil
}

// ProblemReportHandlerFunc handles problem reports
func ProblemReportHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var pr ProblemReport
	if err := json.Unmarshal(ctx.Raw, &pr); err != nil {
		return nil, fmt.Errorf("failed to parse problem report: %w", err)
	}
	logger.GetDefaultLogger().Warnf("⚠️ ProblemReport received (code=%s): %s", pr.Description.Code, pr.Description.En)
	return nil, nil
}
