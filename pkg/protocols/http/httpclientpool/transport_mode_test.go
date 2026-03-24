package httpclientpool

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestNormalizedTLSMode(t *testing.T) {
	t.Run("default-auto", func(t *testing.T) {
		if got := normalizedTLSMode(&types.Options{}); got != tlsModeAuto {
			t.Fatalf("expected %s, got %s", tlsModeAuto, got)
		}
	})

	t.Run("trim-and-lowercase", func(t *testing.T) {
		if got := normalizedTLSMode(&types.Options{TLSMode: "  SSLv3 "}); got != tlsModeSSLv3 {
			t.Fatalf("expected %s, got %s", tlsModeSSLv3, got)
		}
	})
}

func TestValidateTLSMode(t *testing.T) {
	if err := validateTLSMode(&types.Options{TLSMode: "gost"}); err != nil {
		t.Fatalf("expected gost mode to validate: %v", err)
	}
	if err := validateTLSMode(&types.Options{TLSMode: "bogus"}); err == nil {
		t.Fatalf("expected bogus mode to fail validation")
	}
}
