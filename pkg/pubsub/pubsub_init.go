package pubsub

import (
	"context"

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

// Start implements the Runnable interface.
func (r *runner) Start(ctx context.Context) error {
	errCh := make(chan error)
	tools := Tools()
	if len(tools) == 0 {
		log.Info("No pub sub tool is enabled")
		return nil
	}
	log.Info("initializing pub subs")
	client := r.mgr.GetClient()
	for i := range tools {
		pubsub := tools[i]
		go func() {
			if err := pubsub.NewClient(ctx, client); err != nil {
				errCh <- err
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil {
			return err
		}
	}
	return nil
}
