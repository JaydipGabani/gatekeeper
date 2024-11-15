package diskwriter

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/connection"
)

type DiskWriter struct {
	mu      sync.Mutex
	Path    string `json:"path,omitempty"`
	file   *os.File
	lastMessageTime time.Time
	timer           *time.Timer
    timerReset      chan struct{}
}

const (
	Name = "diskwriter"
)

var count int

func (r *DiskWriter) Publish(_ context.Context, data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	if r.file == nil || r.lastMessageTime.Sub(time.Now()) > 20*time.Second {
		// Close the previous file and release the lock if it was open
        if r.file != nil {
            syscall.Flock(int(r.file.Fd()), syscall.LOCK_UN)
            r.file.Close()
        }

        // Open a new file and acquire a lock
        filePath := path.Join(r.Path, "violations.txt")
        file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
        if err != nil {
            return fmt.Errorf("failed to open file: %w", err)
        }

        if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
            file.Close()
            return fmt.Errorf("failed to lock file: %w", err)
        }
		
		r.file = file
        // Initialize the timer and channel if they are nil
        if r.timer == nil {
            r.timer = time.NewTimer(10 * time.Second)
            r.timerReset = make(chan struct{})
            go r.manageLockRelease()
        }
	}

	// Reset the timer
	r.timer.Reset(10 * time.Second)
	r.timerReset <- struct{}{}
	
	_, err = r.file.WriteString(fmt.Sprint("Violation number: ", count, " ") + string(jsonData) + "\n")
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}
	
	log.Printf("%d messages published", count)
	
	count++
	r.lastMessageTime = time.Now()

	return nil
}

func (r *DiskWriter) manageLockRelease() {
    for {
        select {
        case <-r.timer.C:
            r.mu.Lock()
            if r.file != nil {
                syscall.Flock(int(r.file.Fd()), syscall.LOCK_UN)
                r.file.Close()
                r.file = nil
            }
            r.mu.Unlock()
        case <-r.timerReset:
            if !r.timer.Stop() {
                <-r.timer.C
            }
            r.timer.Reset(10 * time.Second)
        }
    }
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
