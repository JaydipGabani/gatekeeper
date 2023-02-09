package pubsub

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/dapr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	flag.Var(pubSubs, "pub-sub-tool", "Preferred pub-sub tool, e.g dapr, rabbitmq. This flag can be declared more than once. Omitting will default to not using any pub sub tool.")
}

var pubSubs = newPubSubSet(map[string]PubSub{
	dapr.Name: &dapr.Dapr{},
},
)

// PubSub is the interface that wraps pubsub methods.
type PubSub interface {
	// Publish single message over a specific topic/channel
	Publish(data interface{}, topic string) error

	// Publish a batch of messages over a specific topic/channel
	PublishBatch(data interface{}, topic string) error

	// Initiate the pub sub client
	NewClient(ctx context.Context, client client.Client) error

	// Get the name of pub sub tool
	GetName() string

	// Determines if publish batching is enabled or not
	IsBatchingEnabled() bool
}

type pubSubSet struct {
	supportedPubSub map[string]PubSub
	enabledPubSub   map[string]PubSub
}

func newPubSubSet(pubSubs map[string]PubSub) *pubSubSet {
	supported := make(map[string]PubSub)
	enabled := make(map[string]PubSub)
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

func (ps *pubSubSet) AddSupportedTool(name string, new PubSub) {
	if _, ok := ps.supportedPubSub[name]; ok {
		panic(fmt.Sprintf("pubsub %v registered twice", name))
	}
	ps.supportedPubSub[name] = new
}

func Tools() []PubSub {
	if len(pubSubs.enabledPubSub) == 0 {
		return []PubSub{}
	}
	ret := make([]PubSub, 0, len(pubSubs.enabledPubSub))
	for _, new := range pubSubs.enabledPubSub {
		ret = append(ret, new)
	}
	return ret
}

// Publish messages to appropriate endpoints using appropriate configure pubsub tool
// input: interface to be published, topic/channel name to publish the message in, source/origin of the message (i.e Audit, Validation, etc)
func Publish(data interface{}, topic string) {
	pubSubs := Tools()
	if len(pubSubs) > 0 {
		for i := range pubSubs {
			toolName := pubSubs[i].GetName()
			log.Info(fmt.Sprintf("Publishing to %s tool", toolName))
			var err error
			if pubSubs[i].IsBatchingEnabled() {
				err = pubSubs[i].PublishBatch(data, topic)
			} else {
				err = pubSubs[i].Publish(data, topic)
			}

			if err != nil {
				log.Error(err, "Not able to publish the message")
			}
		}
	} else {
		log.Info("No pub sub tools are enabled")
	}
}
