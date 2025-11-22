package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RespondJSON writes a JSON response
func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal Server Error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

// ParseShortDuration parses user-friendly durations like "5m", "2h", "1d", "30s",
// and combined forms like "1d2h30m". If an empty string is passed, returns 0, nil.
func ParseShortDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// Regex to capture groups of number+unit (s,m,h,d), case-insensitive
	re := regexp.MustCompile(`(?i)(\d+)([smhd])`)
	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		// Maybe it's a bare number (seconds)
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Duration(v) * time.Second, nil
		}
		return 0, fmt.Errorf("invalid duration format")
	}

	var total time.Duration
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		vStr := m[1]
		unit := strings.ToLower(m[2])
		v, err := strconv.ParseInt(vStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration number: %w", err)
		}

		switch unit {
		case "s":
			total += time.Duration(v) * time.Second
		case "m":
			total += time.Duration(v) * time.Minute
		case "h":
			total += time.Duration(v) * time.Hour
		case "d":
			total += time.Duration(v) * 24 * time.Hour
		default:
			return 0, fmt.Errorf("unknown duration unit: %s", unit)
		}
	}

	return total, nil
}

// MapToJSON converts a Go map to a JSON string for DB storage (Feature 3)
func MapToJSON(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// JSONToMap converts a JSON string from DB to a Go map (Feature 3)
func JSONToMap(s string) (map[string]string, error) {
	if s == "" || s == "null" || s == "{}" {
		return make(map[string]string), nil
	}
	var m map[string]string
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
		log.Printf("[WARNING] Failed to parse envVars JSON: %v. JSON string: %s", err, s)
		// Return empty map on error to prevent execution failure due to bad DB data
		return make(map[string]string), nil
	}
	return m, nil
}

// GetNumericJobID converts "job-ID" to int
func GetNumericJobID(jobID string) (int, error) {
	var numericID int
	if _, err := fmt.Sscanf(jobID, "job-%d", &numericID); err != nil {
		return 0, fmt.Errorf("invalid job ID format: %s", jobID)
	}
	return numericID, nil
}
