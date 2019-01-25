package worker

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/oasislabs/ekiden/go/common/service"
)

const proxyTimeout = 2 * time.Second

// NetworkProxy is the common interface for network proxy implementations.
type NetworkProxy interface {
	// Type returns the type of the proxy ("stream" or "dgram").
	Type() string
	// UnixPath returns the path of the unix socket used by this proxy.
	UnixPath() string

	service.BackgroundService
}

type proxyCommon struct {
	service.BaseBackgroundService

	proxyType     string
	localPath     string
	remoteAddress string

	stopCh    chan struct{}
	groupDone sync.WaitGroup // nolint: structcheck
}

type streamProxy struct {
	proxyCommon
}

type dgramProxy struct {
	proxyCommon
}

type httpProxy struct {
	proxyCommon
}

// Type returns the type of this proxy (either "stream" or "dgram").
func (p *proxyCommon) Type() string {
	return p.proxyType
}

// UnixPath returns the Unix socket path on which the proxy is listening.
func (p *proxyCommon) UnixPath() string {
	return p.localPath
}

// Stop triggers a proxy shutdown.
func (p *proxyCommon) Stop() {
	close(p.stopCh)
}

// Cleanup performs the proxy-specific post-termination cleanup.
func (p *proxyCommon) Cleanup() {
	os.Remove(p.UnixPath())
}

func (p *streamProxy) listener(listener net.Listener) {
	defer p.groupDone.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			netError, netOk := err.(net.Error)
			if netOk && netError.Temporary() {
				continue
			}
			p.Logger.Error("error listening for connections", "err", err)
			return
		}
		if conn == nil {
			// Listener socket shut down.
			return
		}
		p.groupDone.Add(1)
		go p.handleConnection(conn)
	}
}

func (p *streamProxy) streamXfer(from, to net.Conn, doneCh chan<- int) {
	defer p.groupDone.Done()
	defer func() { doneCh <- 1 }()

	_, _ = io.Copy(to, from)
}

func (p *streamProxy) handleConnection(innerSocket net.Conn) {
	defer p.groupDone.Done()
	defer innerSocket.Close()

	upstreamSocket, err := net.Dial("tcp", p.remoteAddress)
	if err != nil {
		p.Logger.Error("error establishing connection to upstream", "err", err)
		return
	}
	defer upstreamSocket.Close()

	// Enforce a read/write timeout on both connections to avoid getting
	// stuck during copy forever.
	_ = innerSocket.SetDeadline(time.Now().Add(proxyTimeout))
	_ = upstreamSocket.SetDeadline(time.Now().Add(proxyTimeout))

	transfers := 2
	streamCloseCh := make(chan int)
	defer close(streamCloseCh)
	p.groupDone.Add(2)
	go p.streamXfer(innerSocket, upstreamSocket, streamCloseCh)
	go p.streamXfer(upstreamSocket, innerSocket, streamCloseCh)

	for {
		select {
		case <-streamCloseCh:
			innerSocket.Close()
			upstreamSocket.Close()
			transfers--
			if transfers < 1 {
				return
			}

		case <-p.stopCh:
			innerSocket.Close()
			upstreamSocket.Close()
		}
	}
}

// Start makes the proxy start listening on its Unix socket.
func (p *streamProxy) Start() error {
	err := os.Remove(p.localPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	listener, err := net.Listen("unix", p.localPath)
	if err != nil {
		p.BaseBackgroundService.Stop()
		return err
	}
	p.groupDone.Add(1)
	go func() {
		defer p.groupDone.Done()
		p.groupDone.Add(1)
		go p.listener(listener)
		<-p.stopCh
		listener.Close()
	}()
	p.Logger.Debug("proxy started")

	go func() {
		p.groupDone.Wait()
		p.BaseBackgroundService.Stop()
		p.Logger.Debug("proxy stopped")
	}()
	return nil
}

func (p *dgramProxy) dgramXfer(from *net.UnixConn, to net.Conn) {
	defer p.groupDone.Done()
	defer to.Close()

	var buffer [65536]byte
	for {
		n, _, err := from.ReadFromUnix(buffer[:])
		if err != nil {
			netErr, netOk := err.(net.Error)
			if netOk && netErr.Temporary() {
				continue
			}
			p.Logger.Error("error receiving", "err", err)
			return
		}
		for {
			_, err := to.Write(buffer[:n])
			if err != nil {
				netErr, netOk := err.(net.Error)
				if !netOk || !netErr.Temporary() {
					p.Logger.Error("error writing", "err", err)
					return
				}
				continue
			}
			break
		}
	}
}

func (p *dgramProxy) proxy(localSocket *net.UnixConn, remoteSocket net.Conn) {
	defer p.groupDone.Done()
	p.groupDone.Add(1)
	go p.dgramXfer(localSocket, remoteSocket)
	<-p.stopCh
	localSocket.Close()
}

// Start makes the proxy start listening on its Unix socket.
func (p *dgramProxy) Start() error {
	err := os.Remove(p.localPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	localSocket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p.localPath})
	if err != nil {
		p.BaseBackgroundService.Stop()
		return err
	}
	remoteSocket, err := net.Dial("udp", p.remoteAddress)
	if err != nil {
		localSocket.Close()
		p.BaseBackgroundService.Stop()
		return err
	}
	p.groupDone.Add(1)
	go p.proxy(localSocket, remoteSocket)
	p.Logger.Debug("proxy started")

	go func() {
		p.groupDone.Wait()
		p.BaseBackgroundService.Stop()
		p.Logger.Debug("proxy stopped")
	}()
	return nil
}

// Start makes the proxy start listening on its Unix socket.
func (p *httpProxy) Start() error {
	err := os.Remove(p.localPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	listener, err := net.Listen("unix", p.localPath)
	if err != nil {
		p.BaseBackgroundService.Stop()
		return err
	}

	remoteURL, err := url.Parse(p.remoteAddress)
	if err != nil {
		p.BaseBackgroundService.Stop()
		return err
	}

	// Create a new reverse proxy that rewrites the Host header.
	server := &http.Server{
		Handler: &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = remoteURL.Scheme
				req.URL.Host = remoteURL.Host
				req.Host = remoteURL.Host
			},
		},
		ReadTimeout:  proxyTimeout,
		WriteTimeout: proxyTimeout,
	}
	go func() {
		p.Logger.Debug("starting proxy")
		if serr := server.Serve(listener); serr != nil && serr != http.ErrServerClosed {
			p.Logger.Error("error while running proxy server",
				"err", serr,
			)
		}

		p.Logger.Debug("proxy stopped")
		p.BaseBackgroundService.Stop()
	}()
	go func() {
		<-p.stopCh
		p.Logger.Debug("stopping proxy")
		_ = server.Close()
	}()

	return nil
}

// NewNetworkProxy constructs and returns a new proxy instance with the given type, name and addresses.
func NewNetworkProxy(name, proxyType, local, remote string) (NetworkProxy, error) {
	svc := *service.NewBaseBackgroundService("proxy/" + name)
	switch proxyType {
	case "stream":
		return &streamProxy{
			proxyCommon: proxyCommon{
				BaseBackgroundService: svc,
				proxyType:             proxyType,
				localPath:             local,
				remoteAddress:         remote,
				stopCh:                make(chan struct{}),
			},
		}, nil

	case "dgram":
		return &dgramProxy{
			proxyCommon: proxyCommon{
				BaseBackgroundService: svc,
				proxyType:             proxyType,
				localPath:             local,
				remoteAddress:         remote,
				stopCh:                make(chan struct{}),
			},
		}, nil

	case "http":
		return &httpProxy{
			proxyCommon: proxyCommon{
				BaseBackgroundService: svc,
				proxyType:             "stream",
				localPath:             local,
				remoteAddress:         remote,
				stopCh:                make(chan struct{}),
			},
		}, nil

	default:
		return nil, errors.New("unknown proxy type " + proxyType)
	}
}
