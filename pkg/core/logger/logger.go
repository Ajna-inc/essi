package logger

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogLevel represents logging levels
type LogLevel int

const (
	// OffLevel turns off logging
	OffLevel LogLevel = iota
	// FatalLevel level. Logs and then calls `logger.Exit(1)`. Highest level of severity.
	FatalLevel
	// ErrorLevel level. Used for errors that should definitely be noted.
	ErrorLevel
	// WarnLevel level. Non-critical entries that deserve eyes.
	WarnLevel
	// InfoLevel level. General operational entries about what's happening inside the application.
	InfoLevel
	// DebugLevel level. Usually only enabled when debugging.
	DebugLevel
	// TraceLevel level. Designates finer-grained informational events than the Debug.
	TraceLevel
)

func (l LogLevel) String() string {
	switch l {
	case OffLevel:
		return "off"
	case FatalLevel:
		return "fatal"
	case ErrorLevel:
		return "error"
	case WarnLevel:
		return "warn"
	case InfoLevel:
		return "info"
	case DebugLevel:
		return "debug"
	case TraceLevel:
		return "trace"
	default:
		return "unknown"
	}
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "off":
		return OffLevel
	case "fatal":
		return FatalLevel
	case "error":
		return ErrorLevel
	case "warn", "warning":
		return WarnLevel
	case "info":
		return InfoLevel
	case "debug":
		return DebugLevel
	case "trace":
		return TraceLevel
	default:
		return InfoLevel
	}
}

// Logger interface defines the logging contract
type Logger interface {
	Fatal(args ...interface{})
	Fatalf(template string, args ...interface{})
	Error(args ...interface{})
	Errorf(template string, args ...interface{})
	Warn(args ...interface{})
	Warnf(template string, args ...interface{})
	Info(args ...interface{})
	Infof(template string, args ...interface{})
	Debug(args ...interface{})
	Debugf(template string, args ...interface{})
	Trace(args ...interface{})
	Tracef(template string, args ...interface{})
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
	WithContext(ctx context.Context) Logger
}

// DefaultLogger is the default logger implementation using logrus
type DefaultLogger struct {
	logger *logrus.Logger
	entry  *logrus.Entry
	level  LogLevel
}

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	logger := logrus.New()

	switch level {
	case OffLevel:
		logger.SetLevel(logrus.PanicLevel + 1) // Disable all logging
	case FatalLevel:
		logger.SetLevel(logrus.FatalLevel)
	case ErrorLevel:
		logger.SetLevel(logrus.ErrorLevel)
	case WarnLevel:
		logger.SetLevel(logrus.WarnLevel)
	case InfoLevel:
		logger.SetLevel(logrus.InfoLevel)
	case DebugLevel:
		logger.SetLevel(logrus.DebugLevel)
	case TraceLevel:
		logger.SetLevel(logrus.TraceLevel)
	}

	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z",
	})

	logger.SetOutput(os.Stdout)

	return &DefaultLogger{
		logger: logger,
		entry:  logrus.NewEntry(logger),
		level:  level,
	}
}

func (l *DefaultLogger) Fatal(args ...interface{}) {
	if l.level >= FatalLevel {
		l.entry.Fatal(args...)
	}
}

func (l *DefaultLogger) Fatalf(template string, args ...interface{}) {
	if l.level >= FatalLevel {
		l.entry.Fatalf(template, args...)
	}
}

func (l *DefaultLogger) Error(args ...interface{}) {
	if l.level >= ErrorLevel {
		l.entry.Error(args...)
	}
}

func (l *DefaultLogger) Errorf(template string, args ...interface{}) {
	if l.level >= ErrorLevel {
		l.entry.Errorf(template, args...)
	}
}

func (l *DefaultLogger) Warn(args ...interface{}) {
	if l.level >= WarnLevel {
		l.entry.Warn(args...)
	}
}

func (l *DefaultLogger) Warnf(template string, args ...interface{}) {
	if l.level >= WarnLevel {
		l.entry.Warnf(template, args...)
	}
}

func (l *DefaultLogger) Info(args ...interface{}) {
	if l.level >= InfoLevel {
		l.entry.Info(args...)
	}
}

func (l *DefaultLogger) Infof(template string, args ...interface{}) {
	if l.level >= InfoLevel {
		l.entry.Infof(template, args...)
	}
}

func (l *DefaultLogger) Debug(args ...interface{}) {
	if l.level >= DebugLevel {
		l.entry.Debug(args...)
	}
}

func (l *DefaultLogger) Debugf(template string, args ...interface{}) {
	if l.level >= DebugLevel {
		l.entry.Debugf(template, args...)
	}
}

func (l *DefaultLogger) Trace(args ...interface{}) {
	if l.level >= TraceLevel {
		l.entry.Trace(args...)
	}
}

func (l *DefaultLogger) Tracef(template string, args ...interface{}) {
	if l.level >= TraceLevel {
		l.entry.Tracef(template, args...)
	}
}

func (l *DefaultLogger) WithField(key string, value interface{}) Logger {
	return &DefaultLogger{
		logger: l.logger,
		entry:  l.entry.WithField(key, value),
		level:  l.level,
	}
}

func (l *DefaultLogger) WithFields(fields map[string]interface{}) Logger {
	return &DefaultLogger{
		logger: l.logger,
		entry:  l.entry.WithFields(fields),
		level:  l.level,
	}
}

func (l *DefaultLogger) WithContext(ctx context.Context) Logger {
	return &DefaultLogger{
		logger: l.logger,
		entry:  l.entry.WithContext(ctx),
		level:  l.level,
	}
}

// ConsoleLogger is a simple console logger for development
type ConsoleLogger struct {
	level LogLevel
}

// NewConsoleLogger creates a new console logger
func NewConsoleLogger(level LogLevel) *ConsoleLogger {
	return &ConsoleLogger{level: level}
}

func (l *ConsoleLogger) log(level LogLevel, format string, args ...interface{}) {
	if l.level >= level {
		prefix := fmt.Sprintf("[%s]", strings.ToUpper(level.String()))
		if format != "" {
			fmt.Printf("%s "+format+"\n", append([]interface{}{prefix}, args...)...)
		} else {
			fmt.Printf("%s %v\n", prefix, args)
		}
	}
}

func (l *ConsoleLogger) Fatal(args ...interface{}) {
	l.log(FatalLevel, "", args...)
	os.Exit(1)
}

func (l *ConsoleLogger) Fatalf(template string, args ...interface{}) {
	l.log(FatalLevel, template, args...)
	os.Exit(1)
}

func (l *ConsoleLogger) Error(args ...interface{}) {
	l.log(ErrorLevel, "", args...)
}

func (l *ConsoleLogger) Errorf(template string, args ...interface{}) {
	l.log(ErrorLevel, template, args...)
}

func (l *ConsoleLogger) Warn(args ...interface{}) {
	l.log(WarnLevel, "", args...)
}

func (l *ConsoleLogger) Warnf(template string, args ...interface{}) {
	l.log(WarnLevel, template, args...)
}

func (l *ConsoleLogger) Info(args ...interface{}) {
	l.log(InfoLevel, "", args...)
}

func (l *ConsoleLogger) Infof(template string, args ...interface{}) {
	l.log(InfoLevel, template, args...)
}

func (l *ConsoleLogger) Debug(args ...interface{}) {
	l.log(DebugLevel, "", args...)
}

func (l *ConsoleLogger) Debugf(template string, args ...interface{}) {
	l.log(DebugLevel, template, args...)
}

func (l *ConsoleLogger) Trace(args ...interface{}) {
	l.log(TraceLevel, "", args...)
}

func (l *ConsoleLogger) Tracef(template string, args ...interface{}) {
	l.log(TraceLevel, template, args...)
}

func (l *ConsoleLogger) WithField(key string, value interface{}) Logger {
	// Simple implementation - could be enhanced
	return l
}

func (l *ConsoleLogger) WithFields(fields map[string]interface{}) Logger {
	// Simple implementation - could be enhanced
	return l
}

func (l *ConsoleLogger) WithContext(ctx context.Context) Logger {
	return l
}

// Global logger instance
var defaultLogger Logger = NewDefaultLogger(InfoLevel)

// SetDefaultLogger sets the global default logger
func SetDefaultLogger(logger Logger) {
	defaultLogger = logger
}

// GetDefaultLogger returns the global default logger
func GetDefaultLogger() Logger {
	return defaultLogger
}

// Global convenience functions
func Fatal(args ...interface{})                       { defaultLogger.Fatal(args...) }
func Fatalf(template string, args ...interface{})     { defaultLogger.Fatalf(template, args...) }
func Error(args ...interface{})                       { defaultLogger.Error(args...) }
func Errorf(template string, args ...interface{})     { defaultLogger.Errorf(template, args...) }
func Warn(args ...interface{})                        { defaultLogger.Warn(args...) }
func Warnf(template string, args ...interface{})      { defaultLogger.Warnf(template, args...) }
func Info(args ...interface{})                        { defaultLogger.Info(args...) }
func Infof(template string, args ...interface{})      { defaultLogger.Infof(template, args...) }
func Debug(args ...interface{})                       { defaultLogger.Debug(args...) }
func Debugf(template string, args ...interface{})     { defaultLogger.Debugf(template, args...) }
func Trace(args ...interface{})                       { defaultLogger.Trace(args...) }
func Tracef(template string, args ...interface{})     { defaultLogger.Tracef(template, args...) }
func WithField(key string, value interface{}) Logger  { return defaultLogger.WithField(key, value) }
func WithFields(fields map[string]interface{}) Logger { return defaultLogger.WithFields(fields) }
func WithContext(ctx context.Context) Logger          { return defaultLogger.WithContext(ctx) }
