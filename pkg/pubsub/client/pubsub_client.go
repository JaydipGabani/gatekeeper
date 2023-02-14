package client

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/dapr"
)

func init() {
	flag.Var(pubSubs, "pub-sub-tool", "Preferred pub-sub tool, e.g dapr, rabbitmq. This flag can be declared more than once. Omitting will default to not using any pub sub tool.")
}

var pubSubs = newPubSubSet(map[string]InitiateClient{
	dapr.Name: dapr.NewClient,
},
)

// PubSub is the interface that wraps pubsub methods.
type PubSub interface {
	// Publish single message over a specific topic/channel
	Publish(data interface{}, topic string) error

	// Publish a batch of messages over a specific topic/channel
	PublishBatch(data interface{}, topic string) error

	// Get the name of pub sub tool
	GetName() string

	// Determines if publish batching is enabled or not
	IsBatchingEnabled() bool
}

type pubSubSet struct {
	supportedPubSub map[string]InitiateClient
	enabledPubSub   map[string]InitiateClient
}

type InitiateClient func(context.Context, string) (interface{}, error)

func newPubSubSet(pubSubs map[string]InitiateClient) *pubSubSet {
	supported := make(map[string]InitiateClient)
	enabled := make(map[string]InitiateClient)
	set := &pubSubSet{
		supportedPubSub: supported,
		enabledPubSub:   enabled,
	}
	for name := range pubSubs {
		set.AddSupportedTool(name, pubSubs[name])
	}
	return set
}

func (ps *pubSubSet) String() string {
	pubSubNames := make([]string, 0)
	for name := range ps.supportedPubSub {
		pubSubNames = append(pubSubNames, name)
	}
	return fmt.Sprintf("%s", pubSubNames)
}

func (ps *pubSubSet) Set(s string) error {
	splt := strings.Split(s, ",")
	for _, v := range splt {
		lower := strings.ToLower(v)
		new, ok := ps.supportedPubSub[lower]
		if !ok {
			return fmt.Errorf("PubSub tool %s is not supported", lower)
		}
		ps.enabledPubSub[lower] = new
	}
	return nil
}

func (ps *pubSubSet) AddSupportedTool(name string, new InitiateClient) {
	if _, ok := ps.supportedPubSub[name]; ok {
		panic(fmt.Sprintf("pubsub %v registered twice", name))
	}
	ps.supportedPubSub[name] = new
}

func Tools() map[string]InitiateClient {
	if len(pubSubs.enabledPubSub) == 0 {
		return map[string]InitiateClient{}
	}
	ret := make(map[string]InitiateClient)
	for name, new := range pubSubs.enabledPubSub {
		ret[name] = new
	}
	return ret
}
