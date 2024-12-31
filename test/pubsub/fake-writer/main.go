package main

import (
	"fmt"
	"os"
	"syscall"
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

func main() {
	path := "/mount/d/go/src/github.com/open-policy-agent/gatekeeper/violations.txt"
	msgId := 1

	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Println("failed to open file: %w", err)
		}

		// Acquire an exclusive lock on the file
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			fmt.Println("failed to lock file: %w", err)
		}

		_, err = file.WriteString(fmt.Sprintf("violation_msg_", msgId) + "\n")
		if err != nil {
			fmt.Println("error publishing message to dapr: %w", err)
		}

		// Release the lock
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			fmt.Println("Error unlocking file: %v\n", err)
		}

		// Close the file
		if err := file.Close(); err != nil {
			fmt.Println("Error closing file: %v\n", err)
		}
		fmt.Println("Published message: violation_msg_", msgId)
		msgId++
	}
}
