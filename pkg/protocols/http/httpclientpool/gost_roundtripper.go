package httpclientpool

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type gostRoundTripper struct {
	fallback http.RoundTripper
	options  *types.Options
	timeout  time.Duration
}

func newGOSTRoundTripper(options *types.Options, fallback http.RoundTripper, timeout time.Duration) (http.RoundTripper, error) {
	if options.AliveHttpProxy != "" || options.AliveSocksProxy != "" {
		return nil, fmt.Errorf("tls-mode=gost does not support proxy transports yet")
	}
	if options.ForceAttemptHTTP2 {
		return nil, fmt.Errorf("tls-mode=gost does not support http2")
	}
	if options.TlsImpersonate {
		return nil, fmt.Errorf("tls-mode=gost does not support tls impersonation")
	}
	if options.HasClientCertificates() {
		return nil, fmt.Errorf("tls-mode=gost does not support client certificates yet")
	}
	return &gostRoundTripper{
		fallback: fallback,
		options:  options,
		timeout:  timeout,
	}, nil
}

func (g *gostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("request url is missing")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return g.fallback.RoundTrip(req)
	}

	address := req.URL.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	serverName := g.options.SNI
	if serverName == "" {
		serverName = req.URL.Hostname()
	}

	args := buildGOSTOpenSSLArgs(address, serverName)
	cmdCtx, cancel := context.WithTimeout(req.Context(), g.timeout)
	cmd := exec.CommandContext(cmdCtx, g.gostOpenSSLBinary(), args...)
	cmd.Env = g.commandEnv()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create openssl stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create openssl stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, formatGOSTCommandError(err, stderr.String())
	}

	request := req.Clone(req.Context())
	request.Close = true
	request.Header = req.Header.Clone()
	request.Header.Set("Connection", "close")

	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		defer func() {
			_ = stdin.Close()
		}()
		writeErr <- request.Write(stdin)
	}()

	reader := bufio.NewReader(stdout)
	response, err := readOpenSSLHTTPResponse(reader, request)
	if err != nil {
		_ = cmd.Process.Kill()
		cancel()
		_ = cmd.Wait()
		return nil, formatGOSTCommandError(err, stderr.String())
	}
	if err := <-writeErr; err != nil {
		_ = cmd.Process.Kill()
		cancel()
		_ = cmd.Wait()
		return nil, formatGOSTCommandError(err, stderr.String())
	}

	response.Request = request
	response.Body = &gostCommandBody{
		ReadCloser: response.Body,
		cancel:     cancel,
		cmd:        cmd,
		stderr:     &stderr,
	}
	return response, nil
}

func (g *gostRoundTripper) gostOpenSSLBinary() string {
	if strings.TrimSpace(g.options.GOSTOpenSSLBinary) != "" {
		return g.options.GOSTOpenSSLBinary
	}
	return "openssl"
}

func (g *gostRoundTripper) commandEnv() []string {
	env := os.Environ()
	if strings.TrimSpace(g.options.GOSTOpenSSLConfig) != "" {
		env = append(env, "OPENSSL_CONF="+g.options.GOSTOpenSSLConfig)
	}
	return env
}

func buildGOSTOpenSSLArgs(address, serverName string) []string {
	args := []string{
		"s_client",
		"-quiet",
		"-ign_eof",
		"-engine", "gost",
		"-cipher", "ALL:@SECLEVEL=0",
		"-legacy_server_connect",
		"-connect", address,
	}
	if serverName != "" {
		args = append(args, "-servername", serverName)
	}
	return args
}

func readOpenSSLHTTPResponse(reader *bufio.Reader, req *http.Request) (*http.Response, error) {
	statusLine, err := findHTTPStatusLine(reader)
	if err != nil {
		return nil, err
	}
	composite := bufio.NewReader(io.MultiReader(strings.NewReader(statusLine), reader))
	return http.ReadResponse(composite, req)
}

func findHTTPStatusLine(reader *bufio.Reader) (string, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(line, "HTTP/") {
			return line, nil
		}
	}
}

func formatGOSTCommandError(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, stderr)
}

type gostCommandBody struct {
	io.ReadCloser
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	stderr     *bytes.Buffer
	closeOnce  sync.Once
	closeError error
}

func (g *gostCommandBody) Close() error {
	g.closeOnce.Do(func() {
		if g.ReadCloser != nil {
			g.closeError = g.ReadCloser.Close()
		}
		g.cancel()
		if g.cmd.Process != nil {
			_ = g.cmd.Process.Kill()
		}
		if err := g.cmd.Wait(); err != nil && g.closeError == nil {
			g.closeError = formatGOSTCommandError(err, g.stderr.String())
		}
	})
	return g.closeError
}
