package httpclientpool

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestShouldUseSharedHTTPClient(t *testing.T) {
	standardConfig := &Configuration{
		RedirectFlow:  DontFollowRedirect,
		DisableCookie: true,
	}

	t.Run("auto-without-client-certs", func(t *testing.T) {
		if !shouldUseSharedHTTPClient(&types.Options{}, standardConfig) {
			t.Fatalf("expected shared HTTP client to be allowed")
		}
	})

	t.Run("gost-without-client-certs", func(t *testing.T) {
		if shouldUseSharedHTTPClient(&types.Options{TLSMode: "gost"}, standardConfig) {
			t.Fatalf("expected dedicated HTTP client for gost mode")
		}
	})

	t.Run("auto-with-client-certs", func(t *testing.T) {
		if shouldUseSharedHTTPClient(&types.Options{
			ClientCertFile: "/tmp/client.crt",
			ClientKeyFile:  "/tmp/client.key",
			ClientCAFile:   "/tmp/client-ca.crt",
		}, standardConfig) {
			t.Fatalf("expected dedicated HTTP client when client certificates are configured")
		}
	})
}
