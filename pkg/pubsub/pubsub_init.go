package pubsub

import (
	"context"
	"fmt"

	psClient "github.com/open-policy-agent/gatekeeper/pkg/pubsub/client"
	"github.com/open-policy-agent/gatekeeper/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeClient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var log = logf.Log.WithName("pubsub")

var _ manager.Runnable = &runner{}

type runner struct {
	mgr manager.Manager
}

func AddToManager(m manager.Manager) error {
	mr := new(m)
	return m.Add(mr)
}

func new(mgr manager.Manager) *runner {
	mr := &runner{
		mgr: mgr,
	}
	return mr
}

var initiatedTools []psClient.PubSub

// Start implements the Runnable interface.
func (r *runner) Start(ctx context.Context) error {
	tools := psClient.Tools()
	if len(tools) == 0 {
		log.Info("No pub sub tool is enabled")
		return nil
	}
	log.Info("Initializing pub subs")
	client := r.mgr.GetClient()
	for name, newClient := range tools {
		config := corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: util.GetNamespace()}}
		err := client.Get(ctx, kubeClient.ObjectKey{Name: name, Namespace: util.GetNamespace()}, &config)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		tmp, err := newClient(ctx, config.Data["config"])
		if err != nil {
			return err
		}

		tc, ok := tmp.(psClient.PubSub)
		if ok {
			initiatedTools = append(initiatedTools, tc)
		} else {
			log.Error(fmt.Errorf("Failed to convert interface"), "Unable to append client")
		}
	}

	log.Info("Pub sub clients are initialized without error")
	return nil
}

// Publish messages to appropriate endpoints using appropriate configure pubsub tool
// input: interface to be published, topic/channel name to publish the message in, source/origin of the message (i.e Audit, Validation, etc)
func Publish(data interface{}, topic string) {
	if len(initiatedTools) > 0 {
		for i := range initiatedTools {
			toolName := initiatedTools[i].GetName()
			log.Info(fmt.Sprintf("Publishing to %s tool", toolName))
			var err error
			if initiatedTools[i].IsBatchingEnabled() {
				log.Info("Publishing batch message")
				err = initiatedTools[i].PublishBatch(data, topic)
			} else {
				log.Info("Publishing single message")
				err = initiatedTools[i].Publish(data, topic)
			}
			if err != nil {
				log.Error(err, "Not able to publish the message")
			} else {
				log.Info(fmt.Sprintf("Published #%v, on topic %s", data, topic))
			}
		}
	} else {
		log.Info("No pub sub tools are enabled")
	}
}
