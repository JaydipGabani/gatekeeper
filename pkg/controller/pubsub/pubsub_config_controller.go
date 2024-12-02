package pubsub

import (
	"context"
	"flag"
	"fmt"

	connectionv1alpha1 "github.com/open-policy-agent/gatekeeper/v3/apis/connection/v1alpha1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/pubsub"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/watch"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var (
	PubsubEnabled = flag.Bool("enable-pub-sub", false, "Enabled pubsub to publish messages")
	log           = logf.Log.WithName("controller").WithValues(logging.Process, "pubsub_controller")
)

type Adder struct {
	PubsubSystem *pubsub.System
}

func (a *Adder) Add(mgr manager.Manager) error {
	if !*PubsubEnabled {
		return nil
	}
	r := newReconciler(mgr, a.PubsubSystem)
	return add(mgr, r)
}

func (a *Adder) InjectControllerSwitch(_ *watch.ControllerSwitch) {}

func (a *Adder) InjectTracker(_ *readiness.Tracker) {}

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
		source.Kind(mgr.GetCache(), &connectionv1alpha1.Connection{},
			&handler.TypedEnqueueRequestForObject[*connectionv1alpha1.Connection]{}))
}

// +kubebuilder:rbac:groups=connection.gatekeeper.sh,resources=*,verbs=get;list;watch;create;update;patch;delete

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log.Info("Reconcile", "request", request, "namespace", request.Namespace, "name", request.Name)

	deleted := false
	cfg := &connectionv1alpha1.Connection{}
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

	if len(cfg.Spec.Config) == 0 {
		return reconcile.Result{}, fmt.Errorf(fmt.Sprintf("config missing in connection %s, unable to configure respective pubsub", request.NamespacedName))
	}
	if cfg.Spec.Driver == "" {
		return reconcile.Result{}, fmt.Errorf(fmt.Sprintf("missing driver field in connection %s, unable to configure respective pubsub", request.NamespacedName))
	}

	err = r.system.UpsertConnection(ctx, cfg.Spec.Config, request.Name, cfg.Spec.Driver)
	if err != nil {
		return reconcile.Result{}, err
	}

	log.Info("Connection upsert successful", "name", request.Name, "provider", cfg.Spec.Driver)
	return reconcile.Result{}, nil
}
