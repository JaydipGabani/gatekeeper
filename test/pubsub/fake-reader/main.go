package main

import (
	"bufio"
	"log"
	"os"
	"syscall"
	// "fmt".
	"time"
)

type PubsubMsg struct {
	ID                    string            `json:"id,omitempty"`
	Details               interface{}       `json:"details,omitempty"`
	EventType             string            `json:"eventType,omitempty"`
	Group                 string            `json:"group,omitempty"`
	Version               string            `json:"version,omitempty"`
	Kind                  string            `json:"kind,omitempty"`
	Name                  string            `json:"name,omitempty"`
	Namespace             string            `json:"namespace,omitempty"`
	Message               string            `json:"message,omitempty"`
	EnforcementAction     string            `json:"enforcementAction,omitempty"`
	ConstraintAnnotations map[string]string `json:"constraintAnnotations,omitempty"`
	ResourceGroup         string            `json:"resourceGroup,omitempty"`
	ResourceAPIVersion    string            `json:"resourceAPIVersion,omitempty"`
	ResourceKind          string            `json:"resourceKind,omitempty"`
	ResourceNamespace     string            `json:"resourceNamespace,omitempty"`
	ResourceName          string            `json:"resourceName,omitempty"`
	ResourceLabels        map[string]string `json:"resourceLabels,omitempty"`
}

// Modifications for acturate simulation
// varify if violation exists for a constraint owned by policy and then post it - add sleep (2s) for a batch size of 2k violations
// hold 2k violations in variable - read from tmp-violations.txt
// hold tmp file for previous violations
// 2 files
// 1 - GK publish violations
// 1 - policy read violations.
func main() {
	filePath := "/tmp/violations/violations.txt"

	for {
		// Open the file in read-write mode
		file, err := os.OpenFile(filePath, os.O_RDWR, 0o644)
		if err != nil {
			log.Printf("Error opening file: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Acquire an exclusive lock on the file
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			log.Fatalf("Error locking file: %v\n", err)
		}

		// Read the file content
		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file: %v\n", err)
		}

		// Process the read content
		for _, line := range lines {
			log.Printf("Processed line: %s\n", line)
		}

		// Truncate the file to remove the processed content
		if err := file.Truncate(0); err != nil {
			log.Fatalf("Error truncating file: %v\n", err)
		}

		// Release the lock
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			log.Fatalf("Error unlocking file: %v\n", err)
		}

		// Close the file
		if err := file.Close(); err != nil {
			log.Fatalf("Error closing file: %v\n", err)
		}
	}
}
