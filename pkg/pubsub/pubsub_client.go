package pubsub

import (
	"flag"
	"fmt"
    "strings"

	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/dapr"
	"github.com/open-policy-agent/gatekeeper/pkg/pubsub/rabbitmq"

)

func init() {
    flag.Var(pubSubs, "pub-sub-tool","Preferred pub-sub tool, e.g dapr, rabbitmq. This flag can be declared more than once. Omitting will default to not using any pub sub tool.")
}

var pubSubs = newPubSubSet(map[string]PubSub{
        dapr.Name: &dapr.Dapr{},
        rabbitmq.Name: &rabbitmq.RabbitMQ{},
    },
)

// PubSub is the interface that wraps pubsub methods.
type PubSub interface {
    Publish(data interface{}) error
	NewClient() error
}

type pubSubSet struct {
    supportedPubSub map[string]PubSub
    enabledPubSub map[string]PubSub
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
		panic(fmt.Sprintf("exporter %v registered twice", name))
	}
	ps.supportedPubSub[name] = new
}

func PubSubTools() []PubSub {
	if len(pubSubs.enabledPubSub) == 0 {
		return []PubSub{}
	}
	ret := make([]PubSub, 0, len(pubSubs.enabledPubSub))
	for _, new := range pubSubs.enabledPubSub {
		ret = append(ret, new)
	}
	return ret
}

