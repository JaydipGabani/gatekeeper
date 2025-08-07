/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package providerstatus

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	frameworksv1beta1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/apis/status/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/operations"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller").WithValues(logging.Process, "provider_status_controller")

type Adder struct{}

func (a *Adder) InjectTracker(_ *readiness.Tracker) {}

// Add creates a new Provider Status Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func (a *Adder) Add(mgr manager.Manager) error {
	if !operations.IsAssigned(operations.Status) {
		return nil
	}
	r := newReconciler(mgr)
	return add(mgr, r)
}

// newReconciler returns a new reconcile.Reconciler.
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileProviderStatus{
		// Separate reader and writer because manager's default client bypasses the cache for unstructured resources.
		writer:       mgr.GetClient(),
		statusClient: mgr.GetClient(),
		reader:       mgr.GetCache(),
		scheme:       mgr.GetScheme(),
		log:          log,
	}
}

// PodStatusToProviderMapper correlates a ProviderPodStatus with its corresponding provider.
func PodStatusToProviderMapper(selfOnly bool, packerMap handler.MapFunc) handler.TypedMapFunc[*v1beta1.ProviderPodStatus, reconcile.Request] {
	return func(ctx context.Context, obj *v1beta1.ProviderPodStatus) []reconcile.Request {
		labels := obj.GetLabels()
		name, ok := labels[v1beta1.ProviderNameLabel]
		if !ok {
			log.Error(fmt.Errorf("provider status resource with no name label: %s", obj.GetName()), "missing label while attempting to map a provider status resource")
			return nil
		}
		if selfOnly {
			pod, ok := labels[v1beta1.PodLabel]
			if !ok {
				log.Error(fmt.Errorf("provider status resource with no pod label: %s", obj.GetName()), "missing label while attempting to map a provider status resource")
			}
			// Do not attempt to reconcile the resource when other pods have changed their status
			if pod != util.GetPodName() {
				return nil
			}
		}
		provider := &frameworksv1beta1.Provider{}
		provider.SetName(name)
		return packerMap(ctx, provider)
	}
}

func eventPackerMapFunc() handler.TypedMapFunc[*frameworksv1beta1.Provider, reconcile.Request] {
	mf := util.EventPackerMapFunc()
	return func(ctx context.Context, obj *frameworksv1beta1.Provider) []reconcile.Request {
		return mf(ctx, obj)
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler.
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("provider-status-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to ProviderPodStatus
	err = c.Watch(
		source.Kind(mgr.GetCache(), &v1beta1.ProviderPodStatus{},
			handler.TypedEnqueueRequestsFromMapFunc(PodStatusToProviderMapper(false, util.EventPackerMapFunc())),
		))
	if err != nil {
		return err
	}

	// Watch for changes to Provider
	err = c.Watch(
		source.Kind(mgr.GetCache(), &frameworksv1beta1.Provider{},
			handler.TypedEnqueueRequestsFromMapFunc(eventPackerMapFunc())))
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileProviderStatus{}

// ReconcileProviderStatus reconciles a Provider object's status.
type ReconcileProviderStatus struct {
	reader       client.Reader
	writer       client.Writer
	statusClient client.StatusClient
	scheme       *runtime.Scheme
	log          logr.Logger
}

// +kubebuilder:rbac:groups=externaldata.gatekeeper.sh,resources=*,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=status.gatekeeper.sh,resources=*,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads that state of the cluster for ProviderPodStatus objects and reports metrics
// based on the current state. Since the Provider CRD from frameworks doesn't have status,
// we focus on aggregating metrics from the pod status objects.
func (r *ReconcileProviderStatus) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	gvk, unpackedRequest, err := util.UnpackRequest(request)
	if err != nil {
		// Unrecoverable, do not retry.
		log.Error(err, "unpacking request", "request", request)
		return reconcile.Result{}, nil
	}

	// Handle both Provider and ProviderPodStatus resources
	if gvk.Group == v1beta1.ExternalDataGroup {
		// This is a Provider resource - check if it still exists
		instance := &frameworksv1beta1.Provider{}
		if err := r.reader.Get(ctx, unpackedRequest.NamespacedName, instance); err != nil {
			if errors.IsNotFound(err) {
				// Provider was deleted, clean up associated pod status objects
				r.cleanupProviderPodStatuses(ctx, unpackedRequest.Name)
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, err
		}

		r.log.Info("handling provider for status aggregation", "provider", instance.Name)

		// Aggregate status from all pods for this provider
		r.aggregateProviderStatus(ctx, instance.Name, instance.GetUID())
	} else {
		// Unrecoverable, do not retry.
		log.Error(fmt.Errorf("invalid resource group: %s", gvk.Group), "invalid group", "gvk", gvk, "name", unpackedRequest.NamespacedName)
		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, nil
}

// aggregateProviderStatus aggregates status from all ProviderPodStatus objects for a provider.
func (r *ReconcileProviderStatus) aggregateProviderStatus(ctx context.Context, providerName string, providerUID types.UID) {
	sObjs := &v1beta1.ProviderPodStatusList{}
	if err := r.reader.List(
		ctx,
		sObjs,
		client.MatchingLabels{
			v1beta1.ProviderNameLabel: providerName,
		},
		client.InNamespace(util.GetNamespace()),
	); err != nil {
		log.Error(err, "failed to list provider pod status objects", "provider", providerName)
		return
	}

	activeCount := 0
	errorCount := 0

	for i := range sObjs.Items {
		status := &sObjs.Items[i]
		// Only count status objects for the current provider instance
		if status.Status.ProviderUID != providerUID {
			continue
		}

		if status.Status.Active {
			activeCount++
		} else {
			errorCount++
		}
	}

	// TODO: Report metrics when we have a metrics reporter
	log.Info("provider status aggregated", "provider", providerName, "active", activeCount, "error", errorCount)
}

// cleanupProviderPodStatuses removes all ProviderPodStatus objects for a deleted provider.
func (r *ReconcileProviderStatus) cleanupProviderPodStatuses(ctx context.Context, providerName string) {
	sObjs := &v1beta1.ProviderPodStatusList{}
	if err := r.reader.List(
		ctx,
		sObjs,
		client.MatchingLabels{
			v1beta1.ProviderNameLabel: providerName,
		},
		client.InNamespace(util.GetNamespace()),
	); err != nil {
		log.Error(err, "failed to list provider pod status objects for cleanup", "provider", providerName)
		return
	}

	for i := range sObjs.Items {
		status := &sObjs.Items[i]
		if err := r.writer.Delete(ctx, status); err != nil {
			log.Error(err, "failed to delete provider pod status", "status", status.Name)
		}
	}
}
