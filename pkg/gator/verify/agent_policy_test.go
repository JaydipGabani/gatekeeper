package verify

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
)

func TestAgentPolicyCannotPassAdmissionAssertions(t *testing.T) {
	obj := agentpolicytest.TemplateObject(t, agentpolicytest.Template())
	raw, err := obj.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	newClient := func(opts ...gator.Opt) (gator.Client, error) {
		return gator.NewOPAClient(false, opts...)
	}
	runner, err := NewRunner(fstest.MapFS{"template.json": &fstest.MapFile{Data: raw}}, newClient)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClient()
	if err != nil {
		t.Fatal(err)
	}
	err = runner.addTemplate(".", "template.json", client)
	if !errors.Is(err, gator.ErrInvalidSuite) || !strings.Contains(err.Error(), "native enforcement must be tested separately") {
		t.Fatalf("gator verify agent template error = %v, want explicit unsupported request assertions", err)
	}
}
