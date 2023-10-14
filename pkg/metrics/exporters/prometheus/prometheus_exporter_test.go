package prometheus

import (
	"testing"
	"time"
)

func TestPrometheusExporter(t *testing.T) {
	const expectedAddr = ":8888"

	srv := newPromSrv(*prometheusPort)
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			t.Error(err)
		}
	}()

	if srv.Addr != expectedAddr {
		t.Errorf("Expected address %v but got %v", expectedAddr, srv.Addr)
	}
}
