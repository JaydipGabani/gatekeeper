package pubsub

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/expansion"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/mutation"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub"
	psClient "github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub/provider"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/watch"
)

var (
	pubsubEnabled = flag.Bool("enable-pub-sub", false, "Enabled pubsub to publish messages")
	log           = logf.Log.WithName("controller").WithValues(logging.Process, "pubsub_controller")
)

type Adder struct {
	PubsubSystem *pubsub.System
}

func (a *Adder) Add(mgr manager.Manager) error {
	if !*pubsubEnabled {
		return nil
	}
	r := newReconciler(mgr, a.PubsubSystem)
	return add(mgr, r)
}

func (a *Adder) InjectOpa(_ *constraintclient.Client) {}

func (a *Adder) InjectWatchManager(_ *watch.Manager) {}

func (a *Adder) InjectControllerSwitch(_ *watch.ControllerSwitch) {}

func (a *Adder) InjectTracker(_ *readiness.Tracker) {}

func (a *Adder) InjectMutationSystem(_ *mutation.System) {}

func (a *Adder) InjectExpansionSystem(_ *expansion.System) {}

func (a *Adder) InjectProviderCache(_ *externaldata.ProviderCache) {}

func (a *Adder) InjectPubsubSystem(pubsubSystem *pubsub.System) {
	a.PubsubSystem = pubsubSystem
}

type Reconciler struct {
	client.Client
	scheme *runtime.Scheme
	system *pubsub.System
}

func newReconciler(mgr manager.Manager, system *pubsub.System) *Reconciler {
	return &Reconciler{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		system: system,
	}
}

func add(mgr manager.Manager, r reconcile.Reconciler) error {
	c, err := controller.New("pubsub-config-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	return c.Watch(
		&source.Kind{Type: &corev1.ConfigMap{}},
		&handler.EnqueueRequestForObject{},
		predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return e.Object.GetNamespace() == util.GetNamespace()
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return e.ObjectNew.GetNamespace() == util.GetNamespace()
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return e.Object.GetNamespace() == util.GetNamespace()
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return e.Object.GetNamespace() == util.GetNamespace()
			},
		},
	)
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log.Info("Reconcile", "request", request, "namespace", request.Namespace, "name", request.Name)

	deleted := false
	cfg := &corev1.ConfigMap{}
	err := r.Get(ctx, request.NamespacedName, cfg)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		deleted = true
	}

	if deleted {
		err := r.system.CloseConnection(request.Name)
		if err != nil {
			return reconcile.Result{Requeue: true}, err
		}
		log.Info("removed connection", "name", request.Name)
		return reconcile.Result{}, nil
	}

	if len(cfg.Data) == 0 {
		return reconcile.Result{}, fmt.Errorf(fmt.Sprintf("data missing in configmap %s, unable to configure respective pubsub", request.NamespacedName))
	}
	if _, ok := cfg.Data["provider"]; !ok {
		return reconcile.Result{}, fmt.Errorf(fmt.Sprintf("missing provider field in configmap %s, unable to configure respective pubsub", request.NamespacedName))
	}
	var config interface{}
	err = json.Unmarshal([]byte(cfg.Data["config"]), &config)
	if err != nil {
		return reconcile.Result{}, err
	}
	err = r.system.UpsertConnection(ctx, config, request.Name, cfg.Data["provider"])
	if err != nil {
		return reconcile.Result{}, err
	}
	log.Info("Connection upsert successful", "name", request.Name, "provider", cfg.Data["provider"])
	return reconcile.Result{}, nil
}