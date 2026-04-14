package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestValidateTransportCompatibility(t *testing.T) {
	t.Run("allows-default-transport", func(t *testing.T) {
		request := &Request{}
		if err := request.validateTransportCompatibility(&types.Options{}); err != nil {
			t.Fatalf("expected default transport to validate: %v", err)
		}
	})

	t.Run("rejects-unsafe-with-gost", func(t *testing.T) {
		request := &Request{Unsafe: true}
		if err := request.validateTransportCompatibility(&types.Options{TLSMode: "gost"}); err == nil {
			t.Fatalf("expected unsafe request to be rejected in gost mode")
		}
	})

	t.Run("rejects-pipeline-with-gost", func(t *testing.T) {
		request := &Request{Pipeline: true}
		if err := request.validateTransportCompatibility(&types.Options{TLSMode: "gost"}); err == nil {
			t.Fatalf("expected pipelined request to be rejected in gost mode")
		}
	})
}
