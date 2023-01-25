package dapr

import (
	"context"
	"encoding/json"
	"fmt"
    "flag"

	"github.com/dapr/go-sdk/client"
)

const (
	Name = "dapr"
)

var (
    pubSubName = flag.String("dapr-pub-sub-name", "pubSub", "Name of the pubsub component to be used")
    topic = flag.String("dapr-topic", "dapr-channel", "Name of the topic where dapr can publish messages")
)

type Dapr struct {
    client client.Client
}

func (r *Dapr) Publish(data interface{}) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return fmt.Errorf("error marshalling data: %s", err)
    }

    err = r.client.PublishEvent(context.Background(), *pubSubName, *topic, jsonData)
    if err != nil {
        return fmt.Errorf("error publishing message to dapr: %s", err)
    }

    return nil
}

func (r *Dapr) NewClient() error {
    var err error
	r.client, err = client.NewClient()
    return err
}