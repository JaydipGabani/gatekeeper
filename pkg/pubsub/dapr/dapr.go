package dapr

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dapr/go-sdk/client"
	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/common"
	"github.com/open-policy-agent/gatekeeper/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	Name = "dapr"
)

type Endpoint struct {
	// Name of the component to be used for pub sub messaging
	Component string `json:"component"`
}

type ClientConfig struct {
	// Enable, Disable batching per tool
	EnableBatching bool `json:"enableBatching"`

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

func (r *Dapr) NewClient(ctx context.Context, k8sClient kubeClient.Client) error {
	var err error
	config := corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: Name, Namespace: util.GetNamespace()}}
	err = k8sClient.Get(ctx, kubeClient.ObjectKey{Name: Name, Namespace: util.GetNamespace()}, &config)
	if err != nil {
		return err
	}
	cfg := ClientConfig{}
	err = json.Unmarshal([]byte(config.Data["dapr.json"]), &cfg)
	if err != nil {
		return err
	}
	r.name = Name
	r.batchingEnabled = cfg.EnableBatching
	for _, ele := range cfg.Endpoints {
		tmp, err := client.NewClient()
		if err != nil {
			return err
		}
		newClient := Client{
			client:          tmp,
			pubSubComponent: common.GetString(ele.Component, "pub-sub"),
		}
		r.client = append(r.client, newClient)
	}

	return err
}

func (r *Dapr) GetName() string {
	return r.name
}

func (r *Dapr) IsBatchingEnabled() bool {
	return r.batchingEnabled
}
