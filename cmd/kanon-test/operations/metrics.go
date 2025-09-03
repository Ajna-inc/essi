package operations

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metrics tracks timing and performance metrics
type Metrics struct {
	mu      sync.RWMutex
	timings map[string]time.Duration
	started time.Time
}

// NewMetrics creates a new metrics tracker
func NewMetrics() *Metrics {
	return &Metrics{
		timings: make(map[string]time.Duration),
		started: time.Now(),
	}
}

// Record records a timing for a specific operation
func (m *Metrics) Record(operation string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timings[operation] = duration
}

// Start starts timing an operation and returns a function to stop it
func (m *Metrics) Start(operation string) func() {
	start := time.Now()
	return func() {
		m.Record(operation, time.Since(start))
	}
}

// Get returns the duration for a specific operation
func (m *Metrics) Get(operation string) (time.Duration, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	duration, ok := m.timings[operation]
	return duration, ok
}

// GetAll returns all recorded timings
func (m *Metrics) GetAll() map[string]time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	result := make(map[string]time.Duration)
	for k, v := range m.timings {
		result[k] = v
	}
	return result
}

// TotalTime returns the total elapsed time since metrics were created
func (m *Metrics) TotalTime() time.Duration {
	return time.Since(m.started)
}

// PrintSummary prints a formatted summary of all timings
func (m *Metrics) PrintSummary() {
	timings := m.GetAll()
	totalTime := m.TotalTime()
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("TIMING SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	
	// Sort keys for consistent output
	keys := make([]string, 0, len(timings))
	for k := range timings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Group timings by category
	connectionOps := []string{}
	credentialOps := []string{}
	proofOps := []string{}
	otherOps := []string{}
	
	for _, key := range keys {
		if strings.Contains(strings.ToLower(key), "connection") || strings.Contains(strings.ToLower(key), "wait_and_execute") {
			connectionOps = append(connectionOps, key)
		} else if strings.Contains(strings.ToLower(key), "credential") || strings.Contains(strings.ToLower(key), "offer") || strings.Contains(strings.ToLower(key), "issue") {
			credentialOps = append(credentialOps, key)
		} else if strings.Contains(strings.ToLower(key), "proof") || strings.Contains(strings.ToLower(key), "presentation") || strings.Contains(strings.ToLower(key), "request") {
			proofOps = append(proofOps, key)
		} else {
			otherOps = append(otherOps, key)
		}
	}
	
	// Print grouped timings
	if len(connectionOps) > 0 {
		fmt.Println("\n📌 Connection Operations:")
		for _, key := range connectionOps {
			fmt.Printf("  %-28s: %12v\n", key, timings[key])
		}
	}
	
	if len(credentialOps) > 0 {
		fmt.Println("\n🎫 Credential Operations:")
		for _, key := range credentialOps {
			fmt.Printf("  %-28s: %12v\n", key, timings[key])
		}
	}
	
	if len(proofOps) > 0 {
		fmt.Println("\n🔍 Proof Operations:")
		for _, key := range proofOps {
			fmt.Printf("  %-28s: %12v\n", key, timings[key])
		}
	}
	
	if len(otherOps) > 0 {
		fmt.Println("\n📊 Other Operations:")
		for _, key := range otherOps {
			fmt.Printf("  %-28s: %12v\n", key, timings[key])
		}
	}
	
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%-30s: %12v\n", "TOTAL TIME", totalTime)
	fmt.Println(strings.Repeat("=", 60))
}

// PrintOperationBreakdown prints a breakdown of specific operations with percentages
func (m *Metrics) PrintOperationBreakdown(title string, operations []string, totalKey string) {
	timings := m.GetAll()
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", 60))
	
	total, hasTotal := timings[totalKey]
	if !hasTotal && totalKey != "" {
		// Calculate total from individual operations
		for _, op := range operations {
			if duration, ok := timings[op]; ok {
				total += duration
			}
		}
	}
	
	var sumOps time.Duration
	for _, op := range operations {
		if duration, ok := timings[op]; ok {
			fmt.Printf("%-30s: %12v", op, duration)
			if total > 0 {
				percentage := float64(duration) / float64(total) * 100
				fmt.Printf(" (%5.1f%%)", percentage)
			}
			fmt.Println()
			sumOps += duration
		}
	}
	
	if total > 0 {
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("%-30s: %12v\n", "TOTAL", total)
		
		// Show overhead if there's a difference
		overhead := total - sumOps
		if overhead > 0 {
			fmt.Printf("%-30s: %12v", "Overhead/Other", overhead)
			percentage := float64(overhead) / float64(total) * 100
			fmt.Printf(" (%5.1f%%)\n", percentage)
		}
	}
	fmt.Println(strings.Repeat("=", 60))
}

// LogTiming logs a timing with optional details
func (m *Metrics) LogTiming(operation string, duration time.Duration, details ...string) {
	m.Record(operation, duration)
	
	logMsg := fmt.Sprintf("⏱️  %s: %v", operation, duration)
	if len(details) > 0 {
		logMsg += " (" + strings.Join(details, ", ") + ")"
	}
	fmt.Println(logMsg)
}