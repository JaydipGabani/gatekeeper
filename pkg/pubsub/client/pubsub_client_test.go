package client

import (
	"flag"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Validates flags parsing for metrics reporters.
func Test_Flags(t *testing.T) {
	tests := map[string]struct {
		input    []string
		expected map[string]InitiateClient
	}{
		"empty": {
			input:    []string{},
			expected: map[string]InitiateClient{},
		},
		"one": {
			input:    []string{"--pub-sub-tool", "dapr"},
			expected: map[string]InitiateClient{"dapr": pubSubs.supportedPubSub["dapr"]},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pubSubTst := newPubSubSet(pubSubs.supportedPubSub)
			flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
			flagSet.Var(pubSubTst, "pub-sub-tool", "Preferred pub-sub tool, e.g dapr, rabbitmq. This flag can be declared more than once. Omitting will default to not using any pub sub tool.")
			err := flagSet.Parse(tc.input)
			if err != nil {
				t.Errorf("parsing: %v", err)
				return
			}
			if diff := cmp.Diff(tc.expected, pubSubTst.enabledPubSub,
				// this compares the memory addresses of the referenced functions
				cmp.Transformer("interface", func(se InitiateClient) string {
					return fmt.Sprint(se)
				})); diff != "" {
				t.Errorf("unexpected result: %s", diff)
			}
		})
	}
}
