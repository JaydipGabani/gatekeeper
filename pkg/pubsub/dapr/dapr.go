package dapr

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dapr/go-sdk/client"
	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/common"
)

const (
	Name = "dapr"
	componentName = "pubsub"
)

type Endpoint struct {
	// Name of the component to be used for pub sub messaging
	Component string `json:"component"`
}

type ClientConfig struct {
	// Enable, Disable batching per tool
	EnableBatching *bool `json:"enableBatching,omitempty"`

	// Different endpoints to publish messages
	Endpoints []Endpoint `json:"endpoints"`
}

type Client struct {
	client          client.Client
	pubSubComponent string
}

// Dapr represents driver for interacting with pub sub using dapr.
type Dapr struct {
	// Array of clients to talk to different endpoints
	client []Client

	// Name of the pubsub tool
	name string

	// Enable, Disable batching per tool
	batchingEnabled bool
}

func (r *Dapr) Publish(data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	for _, c := range r.client {
		err = c.client.PublishEvent(context.Background(), c.pubSubComponent, topic, jsonData)
		if err != nil {
			return fmt.Errorf("error publishing message to dapr: %w", err)
		}
	}

	return nil
}

func (r *Dapr) PublishBatch(data interface{}, topic string) error {
	return nil
}

func (r *Dapr) GetName() string {
	return r.name
}

func (r *Dapr) IsBatchingEnabled() bool {
	return r.batchingEnabled
}

func getDefaultConfig() string {
	tr := bool(true)
	cfg := ClientConfig{
		EnableBatching: &tr,
		Endpoints: []Endpoint{
			{
				Component: componentName,
			},
		},
	}
	data, _ := json.Marshal(cfg)
	return string(data)
}

func NewClient(ctx context.Context, data string) (interface{}, error) {
	cfg := ClientConfig{}
	if data == "" {
		data = getDefaultConfig()
	}
	err := json.Unmarshal([]byte(data), &cfg)
	if err != nil {
		return nil, err
	}
	r := &Dapr{}
	r.name = Name
	r.batchingEnabled = common.GetBool(cfg.EnableBatching, true)
	for _, ele := range cfg.Endpoints {
		tmp, err := client.NewClient()
		if err != nil {
			return nil, err
		}
		newClient := Client{
			client:          tmp,
			pubSubComponent: common.GetString(ele.Component, componentName),
		}
		r.client = append(r.client, newClient)
	}

	return r, nil
}
