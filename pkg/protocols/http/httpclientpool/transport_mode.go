package httpclientpool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	zmaptls "github.com/zmap/zcrypto/tls"
)

const (
	tlsModeAuto  = "auto"
	tlsModeSSLv3 = "sslv3"
	tlsModeGOST  = "gost"
)

func normalizedTLSMode(options *types.Options) string {
	mode := strings.TrimSpace(strings.ToLower(options.TLSMode))
	if mode == "" {
		return tlsModeAuto
	}
	return mode
}

func validateTLSMode(options *types.Options) error {
	switch normalizedTLSMode(options) {
	case tlsModeAuto, tlsModeSSLv3, tlsModeGOST:
		return nil
	default:
		return fmt.Errorf("unsupported tls mode %q", options.TLSMode)
	}
}

func dialTLSWithMode(ctx context.Context, dialers *protocolstate.Dialers, options *types.Options, network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	switch normalizedTLSMode(options) {
	case tlsModeSSLv3:
		if options.TlsImpersonate {
			return nil, fmt.Errorf("tls impersonation is not supported with tls-mode=sslv3")
		}
		if options.ForceAttemptHTTP2 {
			return nil, fmt.Errorf("http2 is not supported with tls-mode=sslv3")
		}
		ztlsConfig, err := fastdialer.AsZTLSConfig(tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("could not convert tls config to ztls config: %w", err)
		}
		ztlsConfig.MinVersion = zmaptls.VersionSSL30
		ztlsConfig.MaxVersion = zmaptls.VersionSSL30
		return dialers.Fastdialer.DialZTLSWithConfig(ctx, network, addr, ztlsConfig)
	case tlsModeGOST:
		return nil, fmt.Errorf("tls-mode=gost requires the dedicated GOST transport")
	default:
		if options.TlsImpersonate {
			return dialers.Fastdialer.DialTLSWithConfigImpersonate(ctx, network, addr, tlsConfig, impersonate.Random, nil)
		}
		if options.HasClientCertificates() || options.ForceAttemptHTTP2 {
			return dialers.Fastdialer.DialTLSWithConfig(ctx, network, addr, tlsConfig)
		}
		return dialers.Fastdialer.DialTLS(ctx, network, addr)
	}
}
