package diskwriter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/connection"
)

type DiskWriter struct {
	mu      sync.Mutex
	auditId string
	Path    string `json:"path,omitempty"`
}

const (
	Name = "diskwriter"
)

func (r *DiskWriter) Publish(_ context.Context, data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	path := path.Join(r.Path, "violations.txt")

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	defer file.Close()

    // Acquire an exclusive lock on the file
    if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
        return fmt.Errorf("failed to lock file: %w", err)
    }
    defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	r.mu.Lock()
	defer r.mu.Unlock()

	_, err = file.WriteString(string(jsonData) + "\n")
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}

	return nil
}

func (r *DiskWriter) CloseConnection() error {
	return nil
}

func (r *DiskWriter) UpdateConnection(_ context.Context, config interface{}) error {
	// m, ok := config.(map[string]interface{})
	// if !ok {
	// 	return fmt.Errorf("invalid type assertion, config is not in expected format")
	// }
	// path, ok := m["path"].(string)
	// if !ok {
	// 	return fmt.Errorf("failed to get value of path")
	// }
	// r.Path = path
	return nil
}

// Returns a new client for dapr.
func NewConnection(_ context.Context, config interface{}) (connection.Connection, error) {
	var diskWriter DiskWriter
	m, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	diskWriter.Path, ok = m["path"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get value of path")
	}
	return &diskWriter, nil
}
