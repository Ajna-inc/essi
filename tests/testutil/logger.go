package testutil

import (
	"context"
	"testing"

	"github.com/ajna-inc/essi/pkg/core/logger"
)

// TestLogger is a minimal logger that writes to testing.T and captures last messages.
type TestLogger struct {
	T *testing.T
}

func (l *TestLogger) Fatal(args ...interface{})                              { l.T.Log(args...) }
func (l *TestLogger) Fatalf(template string, args ...interface{})            { l.T.Logf(template, args...) }
func (l *TestLogger) Error(args ...interface{})                              { l.T.Log(args...) }
func (l *TestLogger) Errorf(template string, args ...interface{})            { l.T.Logf(template, args...) }
func (l *TestLogger) Warn(args ...interface{})                               { l.T.Log(args...) }
func (l *TestLogger) Warnf(template string, args ...interface{})             { l.T.Logf(template, args...) }
func (l *TestLogger) Info(args ...interface{})                               { l.T.Log(args...) }
func (l *TestLogger) Infof(template string, args ...interface{})             { l.T.Logf(template, args...) }
func (l *TestLogger) Debug(args ...interface{})                              { l.T.Log(args...) }
func (l *TestLogger) Debugf(template string, args ...interface{})            { l.T.Logf(template, args...) }
func (l *TestLogger) Trace(args ...interface{})                              { l.T.Log(args...) }
func (l *TestLogger) Tracef(template string, args ...interface{})            { l.T.Logf(template, args...) }
func (l *TestLogger) WithField(key string, value interface{}) logger.Logger  { return l }
func (l *TestLogger) WithFields(fields map[string]interface{}) logger.Logger { return l }
func (l *TestLogger) WithContext(ctx context.Context) logger.Logger          { return l }
