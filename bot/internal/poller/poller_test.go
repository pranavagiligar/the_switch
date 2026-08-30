package poller

import (
	"os"
	"testing"
)

func TestStateSaveAndLoad(t *testing.T) {
	testFile := "bot_state.json"
	defer os.Remove(testFile)
	defer os.Remove(testFile + ".tmp")

	// Reset state
	executionMutex.Lock()
	lastSeenExecution = make(map[string]string)
	lastSeenExecution["job-1"] = "exec-100"
	lastSeenExecution["job-2"] = "exec-200"
	executionMutex.Unlock()

	// Save state
	saveExecutionState()

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatalf("Expected state file %s to exist", testFile)
	}

	// Clear in-memory state
	executionMutex.Lock()
	lastSeenExecution = make(map[string]string)
	executionMutex.Unlock()

	// Load state back
	loadExecutionState()

	executionMutex.Lock()
	defer executionMutex.Unlock()

	if lastSeenExecution["job-1"] != "exec-100" {
		t.Errorf("Expected job-1 to have exec-100, got %s", lastSeenExecution["job-1"])
	}
	if lastSeenExecution["job-2"] != "exec-200" {
		t.Errorf("Expected job-2 to have exec-200, got %s", lastSeenExecution["job-2"])
	}
}

