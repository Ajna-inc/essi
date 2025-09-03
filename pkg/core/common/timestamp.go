package common

import (
	"time"
)

// CurrentTimestamp returns the current timestamp as ISO 8601 string
func CurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ParseTimestamp parses an ISO 8601 timestamp string
func ParseTimestamp(timestamp string) (time.Time, error) {
	return time.Parse(time.RFC3339, timestamp)
}

// NowUnix returns current Unix timestamp
func NowUnix() int64 {
	return time.Now().Unix()
}