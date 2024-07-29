package eventhub

import (
	"context"
	"fmt"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/connection"
)


// Dapr represents driver for interacting with pub sub using dapr.
type EventHub struct {
	// Array of clients to talk to different endpoints
	producerClient *azeventhubs.ProducerClient

	// Name of the pubsub component
	ConnectionString string `json:"connectionString"`
	EventHubName 	 string `json:"eventHubName"`
}

const (
	Name = "eventhub"
)

func (r *EventHub) Publish(ctx context.Context, data interface{}, topic string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling data: %w", err)
	}

	newBatchOptions := &azeventhubs.EventDataBatchOptions{}

    batch, err := r.producerClient.NewEventDataBatch(context.TODO(), newBatchOptions)
	err = batch.AddEventData(&azeventhubs.EventData{
		Body: jsonData,
	}, nil)
	if err != nil {
		return fmt.Errorf("error adding event data to batch: %w", err)
	}

	err = r.producerClient.SendEventDataBatch(ctx, batch, nil)
	if err != nil {
		return fmt.Errorf("error publishing message to dapr: %w", err)
	}

	return nil
}

func (r *EventHub) CloseConnection() error {
	return nil
}

func (r *EventHub) UpdateConnection(_ context.Context, config interface{}) error {
	cfg, ok := config.(string)
	if !ok {
		return fmt.Errorf("invalid type assertion, config is not in expected format")
	}

	err := json.Unmarshal([]byte(cfg), &r)
	if err != nil {
		return err
	}

	r.producerClient, err = azeventhubs.NewProducerClientFromConnectionString(r.ConnectionString, r.EventHubName, nil)
	if err != nil {
		return err
	}
	return nil
}

// Returns a new client for dapr.
func NewConnection(_ context.Context, config interface{}) (connection.Connection, error) {
	cfg, ok := config.(string)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion, config is not in expected format")
	}
	client := &EventHub{}
	err := json.Unmarshal([]byte(cfg), &client)
	if err != nil {
		return nil, err
	}

	client.producerClient, err = azeventhubs.NewProducerClientFromConnectionString(client.ConnectionString, client.EventHubName, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
