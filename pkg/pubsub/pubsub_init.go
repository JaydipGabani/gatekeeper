package pubsub

import (
	"context"
	
	"sigs.k8s.io/controller-runtime/pkg/manager"
    logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	tools := PubSubTools()
    if len(tools) == 0 {
        log.Info("No pub sub tool is enabled")
        return nil
    }
	for i := range tools {
		pubsub := tools[i]
		go func() {
			if err := pubsub.NewClient(); err != nil {
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