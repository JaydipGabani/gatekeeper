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
	"sort"

	"github.com/go-logr/logr"
	externaldatav1beta1 "github.com/open-policy-agent/gatekeeper/v3/apis/externaldata/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/apis/status/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/operations"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
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

var log = logf.Log.WithName("controller").WithValues(logging.Process, "provider_status_controller")

type Adder struct {
}

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
		provider := &externaldatav1beta1.Provider{}
		provider.SetName(name)
		return packerMap(ctx, provider)
	}
}

func eventPackerMapFunc() handler.TypedMapFunc[*externaldatav1beta1.Provider, reconcile.Request] {
	mf := util.EventPackerMapFunc()
	return func(ctx context.Context, obj *externaldatav1beta1.Provider) []reconcile.Request {
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
		source.Kind(mgr.GetCache(), &externaldatav1beta1.Provider{},
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

// Reconcile reads that state of the cluster for a Provider object and makes changes based on the state read
// and what is in the Provider.Spec.
func (r *ReconcileProviderStatus) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	gvk, unpackedRequest, err := util.UnpackRequest(request)
	if err != nil {
		// Unrecoverable, do not retry.
		log.Error(err, "unpacking request", "request", request)
		return reconcile.Result{}, nil
	}

	// Sanity - make sure it is a provider resource.
	if gvk.Group != v1beta1.ExternalDataGroup {
		// Unrecoverable, do not retry.
		log.Error(err, "invalid provider GroupVersion", "gvk", gvk, "name", unpackedRequest.NamespacedName)
		return reconcile.Result{}, nil
	}

	instance := &externaldatav1beta1.Provider{}
	if err := r.reader.Get(ctx, unpackedRequest.NamespacedName, instance); err != nil {
		// If the provider does not exist, we are done
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	r.log.Info("handling provider status update", "instance", instance)

	sObjs := &v1beta1.ProviderPodStatusList{}
	if err := r.reader.List(
		ctx,
		sObjs,
		client.MatchingLabels{
			v1beta1.ProviderNameLabel: instance.GetName(),
		},
		client.InNamespace(util.GetNamespace()),
	); err != nil {
		return reconcile.Result{}, err
	}

	statusObjs := make(sortableStatuses, len(sObjs.Items))
	copy(statusObjs, sObjs.Items)
	sort.Sort(statusObjs)

	var s []v1beta1.ProviderPodStatusStatus
	for i := range statusObjs {
		// Don't report status if it's not for the correct object. This can happen
		// if a watch gets interrupted, causing the provider status to be deleted
		// out from underneath it
		if statusObjs[i].Status.ProviderUID != instance.GetUID() {
			continue
		}
		s = append(s, statusObjs[i].Status)
	}

	instance.Status.ByPod = s

	if err = r.statusClient.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{Requeue: true}, nil
	}

	return reconcile.Result{}, nil
}

type sortableStatuses []v1beta1.ProviderPodStatus

func (s sortableStatuses) Len() int {
	return len(s)
}

func (s sortableStatuses) Less(i, j int) bool {
	return s[i].Status.ID < s[j].Status.ID
}

func (s sortableStatuses) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}