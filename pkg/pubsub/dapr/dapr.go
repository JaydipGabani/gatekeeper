package dapr

import (
	"context"
	"encoding/json"
	"fmt"

	daprClient "github.com/dapr/go-sdk/client"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/connection"
)

// Dapr represents driver for interacting with pub sub using dapr.
type Dapr struct {
	// Array of clients to talk to different endpoints
	client daprClient.Client

	// Name of the pubsub component
	Component string `json:"component"`
}

const (
	Name = "dapr"
)

func (r *Dapr) Publish(_ context.Context, data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	err = r.client.PublishEvent(context.Background(), r.Component, topic, jsonData)
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}

	return nil
}

func (r *Dapr) CloseConnection() error {
	return nil
}

func (r *Dapr) UpdateConnection(_ context.Context, config interface{}) error {
	dClient := &Dapr{}
	cfg, ok := config.(string)
	if !ok {
		return fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	err := json.Unmarshal([]byte(cfg), &dClient)
	if err != nil {
		return err
	}
	r.Component = dClient.Component
	return nil
}

// Returns a new client for dapr.
func NewConnection(_ context.Context, config interface{}) (connection.Connection, error) {
	dClient := &Dapr{}
	cfg, ok := config.(string)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	err := json.Unmarshal([]byte(cfg), &dClient)
	if err != nil {
		return nil, err
	}

	dClient.client, err = daprClient.NewClient()
	if err != nil {
		return nil, err
	}

	return dClient, nil
}
