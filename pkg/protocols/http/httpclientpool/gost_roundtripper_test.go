package httpclientpool

import (
	"net/http"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestBuildGOSTOpenSSLArgs(t *testing.T) {
	args := buildGOSTOpenSSLArgs("example.com:443", "example.com", nil)
	expected := []string{
		"s_client",
		"-quiet",
		"-ign_eof",
		"-engine", "gost",
		"-cipher", "ALL:@SECLEVEL=0",
		"-legacy_server_connect",
		"-connect", "example.com:443",
		"-servername", "example.com",
	}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d", len(expected), len(args))
	}
	for i := range expected {
		if args[i] != expected[i] {
			t.Fatalf("expected arg %d to be %q, got %q", i, expected[i], args[i])
		}
	}
}

func TestBuildGOSTOpenSSLArgsWithClientCertificates(t *testing.T) {
	args := buildGOSTOpenSSLArgs("example.com:443", "example.com", &types.Options{
		ClientCertFile: "/tmp/client.crt",
		ClientKeyFile:  "/tmp/client.key",
		ClientCAFile:   "/tmp/client-ca.crt",
	})
	expected := []string{
		"s_client",
		"-quiet",
		"-ign_eof",
		"-engine", "gost",
		"-cipher", "ALL:@SECLEVEL=0",
		"-legacy_server_connect",
		"-connect", "example.com:443",
		"-servername", "example.com",
		"-cert", "/tmp/client.crt",
		"-key", "/tmp/client.key",
		"-CAfile", "/tmp/client-ca.crt",
	}
	if len(args) != len(expected) {
		t.Fatalf("expected %d args, got %d", len(expected), len(args))
	}
	for i := range expected {
		if args[i] != expected[i] {
			t.Fatalf("expected arg %d to be %q, got %q", i, expected[i], args[i])
		}
	}
}

func TestNewGOSTRoundTripperValidation(t *testing.T) {
	fallback := http.DefaultTransport
	_, err := newGOSTRoundTripper(&types.Options{ForceAttemptHTTP2: true}, fallback, time.Second)
	if err == nil {
		t.Fatalf("expected http2 configuration to be rejected")
	}
}
