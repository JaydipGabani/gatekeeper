package externaldata

import (
	"context"

	externaldataUnversioned "github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/unversioned"
	externaldatav1beta1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/externaldata/v1beta1"
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	frameworksexternaldata "github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	statusv1beta1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/externaldata"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/logging"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/readiness"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var (
	log = logf.Log.WithName("controller").WithValues(logging.Process, "externaldata_controller")

	gvkExternalData = schema.GroupVersionKind{
		Group:   "externaldata.gatekeeper.sh",
		Version: "v1beta1",
		Kind:    "Provider",
	}
)

type Adder struct {
	CFClient      *constraintclient.Client
	ProviderCache *frameworksexternaldata.ProviderCache
	Tracker       *readiness.Tracker
	GetPod        func(context.Context) (*corev1.Pod, error)
}

func (a *Adder) InjectGetPod(f func(context.Context) (*corev1.Pod, error)) {
	a.GetPod = f
}

func (a *Adder) InjectCFClient(c *constraintclient.Client) {
	a.CFClient = c
}

func (a *Adder) InjectTracker(t *readiness.Tracker) {
	a.Tracker = t
}

func (a *Adder) InjectProviderCache(providerCache *frameworksexternaldata.ProviderCache) {
	a.ProviderCache = providerCache
}

// Add creates a new ExternalData Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func (a *Adder) Add(mgr manager.Manager) error {
	r := newReconciler(mgr, a.CFClient, a.ProviderCache, a.Tracker, a.GetPod)
	return add(mgr, r)
}

// Reconciler reconciles a ExternalData object.
type Reconciler struct {
	client.Client
	cfClient      *constraintclient.Client
	providerCache *frameworksexternaldata.ProviderCache
	tracker       *readiness.Tracker
	scheme        *runtime.Scheme
	getPod        func(context.Context) (*corev1.Pod, error)
}

// newReconciler returns a new reconcile.Reconciler.
func newReconciler(mgr manager.Manager, client *constraintclient.Client, providerCache *frameworksexternaldata.ProviderCache, tracker *readiness.Tracker, getPod func(context.Context) (*corev1.Pod, error)) *Reconciler {
	r := &Reconciler{
		cfClient:      client,
		providerCache: providerCache,
		Client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		tracker:       tracker,
		getPod:        getPod,
	}
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler.
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	if !*externaldata.ExternalDataEnabled {
		return nil
	}

	// Create a new controller
	c, err := controller.New("externaldata-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Provider
	return c.Watch(
		source.Kind(mgr.GetCache(), &externaldatav1beta1.Provider{},
			&handler.TypedEnqueueRequestForObject[*externaldatav1beta1.Provider]{}))
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log.Info("Reconcile", "request", request)

	deleted := false
	provider := &externaldatav1beta1.Provider{}
	err := r.Get(ctx, request.NamespacedName, provider)
	if err != nil {
		if !errors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		deleted = true
		provider = &externaldatav1beta1.Provider{
			ObjectMeta: metav1.ObjectMeta{
				Name: request.Name,
			},
			TypeMeta: metav1.TypeMeta{
				Kind:       "Provider",
				APIVersion: "v1beta1",
			},
		}
	}

	deleted = deleted || !provider.GetDeletionTimestamp().IsZero()
	tracker := r.tracker.For(gvkExternalData)

	unversionedProvider := &externaldataUnversioned.Provider{}
	if err := r.scheme.Convert(provider, unversionedProvider, nil); err != nil {
		log.Error(err, "conversion error")
		// Update status object with conversion error
		r.updateProviderPodStatus(ctx, provider, false, []statusv1beta1.ProviderError{
			{
				Type:           statusv1beta1.ConversionError,
				Message:        err.Error(),
				Retryable:      false,
				ErrorTimestamp: &metav1.Time{Time: metav1.Now().Time},
			},
		})
		return reconcile.Result{}, err
	}

	if !deleted {
		if err := r.providerCache.Upsert(unversionedProvider); err != nil {
			log.Error(err, "Upsert failed", "resource", request.NamespacedName)
			tracker.TryCancelExpect(provider)
			// Update status object with upsert error
			r.updateProviderPodStatus(ctx, provider, false, []statusv1beta1.ProviderError{
				{
					Type:           statusv1beta1.UpsertCacheError,
					Message:        err.Error(),
					Retryable:      true,
					ErrorTimestamp: &metav1.Time{Time: metav1.Now().Time},
				},
			})
			return reconcile.Result{}, err
		}
		tracker.Observe(provider)
		// Update status object with success
		r.updateProviderPodStatus(ctx, provider, true, nil)
	} else {
		r.providerCache.Remove(provider.Name)
		tracker.CancelExpect(provider)
		// Clean up status object
		r.cleanupProviderPodStatus(ctx, provider.Name)
	}

	return ctrl.Result{}, nil
}

// updateProviderPodStatus creates or updates the ProviderPodStatus for this pod
func (r *Reconciler) updateProviderPodStatus(ctx context.Context, provider *externaldatav1beta1.Provider, active bool, providerErrors []statusv1beta1.ProviderError) {
	if r.getPod == nil {
		log.Info("getPod function not available, skipping status update")
		return
	}

	pod, err := r.getPod(ctx)
	if err != nil {
		log.Error(err, "failed to get pod for status update")
		return
	}

	statusObj, err := statusv1beta1.NewProviderStatusForPod(pod, provider.Name, r.scheme)
	if err != nil {
		log.Error(err, "failed to create provider status object")
		return
	}

	statusObj.Status.ProviderUID = provider.GetUID()
	statusObj.Status.Active = active
	statusObj.Status.Errors = providerErrors
	statusObj.Status.ObservedGeneration = provider.GetGeneration()
	now := metav1.Now()
	statusObj.Status.LastTransitionTime = &now
	if active {
		statusObj.Status.LastCacheUpdateTime = &now
	}

	existing := &statusv1beta1.ProviderPodStatus{}
	key := types.NamespacedName{Namespace: statusObj.GetNamespace(), Name: statusObj.GetName()}
	if err := r.Get(ctx, key, existing); err != nil {
		if errors.IsNotFound(err) {
			// Create new status object
			if err := r.Create(ctx, statusObj); err != nil {
				log.Error(err, "failed to create provider pod status")
			}
		} else {
			log.Error(err, "failed to get existing provider pod status")
		}
	} else {
		// Update existing status object
		existing.Status = statusObj.Status
		if err := r.Update(ctx, existing); err != nil {
			log.Error(err, "failed to update provider pod status")
		}
	}
}

// cleanupProviderPodStatus removes the ProviderPodStatus for this pod when provider is deleted
func (r *Reconciler) cleanupProviderPodStatus(ctx context.Context, providerName string) {
	if r.getPod == nil {
		return
	}

	pod, err := r.getPod(ctx)
	if err != nil {
		log.Error(err, "failed to get pod for status cleanup")
		return
	}

	key, err := statusv1beta1.KeyForProvider(pod.Name, providerName)
	if err != nil {
		log.Error(err, "failed to generate key for provider status cleanup")
		return
	}

	statusObj := &statusv1beta1.ProviderPodStatus{}
	objKey := types.NamespacedName{Namespace: util.GetNamespace(), Name: key}
	if err := r.Get(ctx, objKey, statusObj); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "failed to get provider pod status for cleanup")
		}
		return
	}

	if err := r.Delete(ctx, statusObj); err != nil {
		log.Error(err, "failed to delete provider pod status")
	}
}
