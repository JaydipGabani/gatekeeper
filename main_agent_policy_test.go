package main

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/agentpolicy"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAgentPolicyTargetOptInRegistration(t *testing.T) {
	if got := flag.Lookup("enable-agent-policy-target").DefValue; got != "false" {
		t.Fatalf("flag default = %q, want false", got)
	}
	if agentpolicy.EnforcementPoint != util.AgentEnforcementPoint {
		t.Fatalf("agent status and enforcement-point validation disagree")
	}
	mapper := meta.NewDefaultRESTMapper(nil)
	objects := agentpolicy.NewOfflineDriver().WatchObjects()
	if len(objects) != 2 {
		t.Fatalf("native watches = %d, want both policy APIs", len(objects))
	}
	for _, obj := range objects {
		mapper.Add(obj.GetObjectKind().GroupVersionKind(), meta.RESTScopeNamespace)
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			var discovery meta.RESTMapper
			if enabled {
				discovery = mapper
			}
			nativeClient := clientfake.NewClientBuilder().Build()
			opts, driver, err := agentPolicyClientOptions(enabled, nativeClient, nativeClient, discovery, []handler.TargetHandler{&target.K8sValidationTarget{}})
			if err != nil {
				t.Fatal(err)
			}
			if (driver != nil) != enabled {
				t.Fatalf("driver = %v, enabled = %v", driver, enabled)
			}
			regoDriver, err := rego.New()
			if err != nil {
				t.Fatal(err)
			}
			opts = append(opts, constraintclient.Driver(regoDriver), constraintclient.EnforcementPoints(util.WebhookEnforcementPoint))
			c, err := constraintclient.NewClient(opts...)
			if err != nil {
				t.Fatal(err)
			}
			ct := agentpolicytest.Template()
			_, err = c.CreateCRD(context.Background(), ct)
			if enabled && err != nil {
				t.Fatalf("enabled target was not registered: %v", err)
			}
			if !enabled && (err == nil || !strings.Contains(err.Error(), "not recognized")) {
				t.Fatalf("disabled target error = %v, want unrecognized target", err)
			}
			if enabled {
				if _, err := c.AddTemplate(context.Background(), ct); err != nil {
					t.Fatalf("enabled AgentPolicy driver could not load template: %v", err)
				}
				if _, err := c.AddConstraint(context.Background(), agentpolicytest.Constraint()); err != nil {
					t.Fatalf("enabled AgentPolicy driver could not load Constraint: %v", err)
				}
			}
			ct.Spec.Targets[0].Target = target.Name
			if _, err := c.CreateCRD(context.Background(), ct); err != nil {
				t.Fatalf("Kubernetes admission target was replaced: %v", err)
			}
			if enabled {
				_, err := constraintclient.NewClient(append(opts, constraintclient.Driver(driver))...)
				if !errors.Is(err, constraintclient.ErrDuplicateDriver) {
					t.Fatalf("registered AgentPolicy driver was not detected as duplicate: %v", err)
				}
			}
		})
	}
}

func TestAgentPolicyStartupRequiresBothNativeAPIs(t *testing.T) {
	objects := agentpolicy.NewOfflineDriver().WatchObjects()
	for missing := range objects {
		gvk := objects[missing].GetObjectKind().GroupVersionKind()
		t.Run(gvk.String(), func(t *testing.T) {
			mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{})
			for i, obj := range objects {
				if i != missing {
					mapper.Add(obj.GetObjectKind().GroupVersionKind(), meta.RESTScopeNamespace)
				}
			}
			nativeClient := clientfake.NewClientBuilder().Build()
			_, driver, err := agentPolicyClientOptions(true, nativeClient, nativeClient, mapper, []handler.TargetHandler{&target.K8sValidationTarget{}})
			if err == nil || !strings.Contains(err.Error(), "requires preinstalled "+gvk.String()+" CRD") || !meta.IsNoMatchError(err) {
				t.Fatalf("startup without %s error = %v", gvk, err)
			}
			if driver != nil {
				t.Fatal("partially initialized driver escaped failed startup")
			}
		})
	}
}
