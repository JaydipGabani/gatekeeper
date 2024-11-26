package diskwriter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"syscall"
	"time"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/connection"
)

type DiskWriter struct {
	Path    string `json:"path,omitempty"`
	file   *os.File
}

const (
	Name = "diskwriter"
)

func (r *DiskWriter) Publish(_ context.Context, data interface{}, _ string) error {
	if msg, ok := data.(string); ok && msg == "audit is completed" {	
		// release lock
		err := syscall.Flock(int(r.file.Fd()), syscall.LOCK_UN)
		r.file.Close()
		r.file = nil
		return err
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	if r.file == nil {
        // Open a new file and acquire a lock
        filePath := path.Join(r.Path, "violations.txt")
        file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            return fmt.Errorf("failed to open file: %w", err)
        }

        for {
            err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
            if err == nil {
                break
            }
            time.Sleep(100 * time.Millisecond) // Sleep for a short duration before retrying
        }
		
		r.file = file
		err = r.file.Truncate(0)
		if err != nil {
			r.file = nil
            return fmt.Errorf("failed to truncate file: %w", err)
        }
	}
	
	_, err = r.file.WriteString(string(jsonData) + "\n")
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}

	return nil
}

func (r *DiskWriter) CloseConnection() error {
	return nil
}

func (r *DiskWriter) UpdateConnection(_ context.Context, _ interface{}) error {
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
