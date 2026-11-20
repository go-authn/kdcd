// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-authn/kdc"
)

// Daemon is a running KDC: its sockets and the goroutines serving them.
type Daemon struct {
	srv     *kdc.Server
	rt      *Runtime
	tcp     net.Listener
	udp     net.PacketConn
	mintLn  net.Listener
	mintSrv *http.Server
	kkLn    net.Listener
	kkSrv   *http.Server

	errc chan error
	once sync.Once
	wg   sync.WaitGroup
}

// Start listens and serves. The sockets are open when it returns, so a caller
// that asked for port 0 can read the ports back with KDCAddr and MintAddr.
func Start(rt *Runtime, logf func(format string, args ...any)) (*Daemon, error) {
	c := rt.Cfg
	srv, err := kdc.New(kdc.Config{
		Realm:       c.Realm,
		People:      rt.People,
		Services:    rt.Keytab,
		Lifetime:    c.Lifetime,
		MaxSkew:     c.MaxSkew,
		MintCallers: mintCallers(c),
		Logf:        logf,
	})
	if err != nil {
		return nil, err
	}
	d := &Daemon{srv: srv, rt: rt, errc: make(chan error, 3)}
	if d.tcp, d.udp, err = listenKDC(c.KDCAddr); err != nil {
		return nil, err
	}
	if c.Mint != nil {
		ln, err := net.Listen("tcp", c.Mint.Addr)
		if err != nil {
			d.tcp.Close()
			d.udp.Close()
			return nil, fmt.Errorf("mint listener %s: %w", c.Mint.Addr, err)
		}
		d.mintLn = tls.NewListener(ln, rt.TLS)
		mux := http.NewServeMux()
		// Only /mint: the handler is the library's, and nothing else is served.
		mux.Handle("/mint", srv.MintHandler())
		d.mintSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			// A client without a certificate fails the handshake; the default
			// logger would print each such attempt as a line of noise.
			ErrorLog: log.New(discard{}, "", 0),
		}
	}

	if k := c.KKDCP; k != nil {
		ln, err := net.Listen("tcp", k.Addr)
		if err != nil {
			d.tcp.Close()
			d.udp.Close()
			if d.mintLn != nil {
				d.mintLn.Close()
			}
			return nil, fmt.Errorf("kkdcp listener %s: %w", k.Addr, err)
		}
		d.kkLn = ln
		mux := http.NewServeMux()
		// Only the one path, POST-only inside the handler; nothing else is served.
		mux.Handle(k.Path, srv.KKDCPHandler())
		d.kkSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          log.New(discard{}, "", 0),
		}
	}

	d.serve("kdc udp", func() error { return srv.ServeUDP(d.udp) })
	d.serve("kdc tcp", func() error { return srv.ServeTCP(d.tcp) })
	if d.mintSrv != nil {
		d.serve("mint", func() error { return d.mintSrv.Serve(d.mintLn) })
	}
	if d.kkSrv != nil {
		d.serve("kkdcp", func() error { return d.kkSrv.Serve(d.kkLn) })
	}
	return d, nil
}

func mintCallers(c *Config) []string {
	if c.Mint == nil {
		return nil
	}
	return c.Mint.Callers
}

func (d *Daemon) serve(what string, f func() error) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		err := f()
		if err == nil || errors.Is(err, kdc.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return
		}
		select {
		case d.errc <- fmt.Errorf("%s: %w", what, err):
		default:
		}
	}()
}

// Err delivers the first fatal error of a serving goroutine.
func (d *Daemon) Err() <-chan error { return d.errc }

// KDCAddr is where the KDC answers, on TCP and on UDP.
func (d *Daemon) KDCAddr() string { return d.tcp.Addr().String() }

// MintAddr is where the mint listener answers, "" when it is off.
func (d *Daemon) MintAddr() string {
	if d.mintLn == nil {
		return ""
	}
	return d.mintLn.Addr().String()
}

// KKDCPAddr is where the MS-KKDCP listener answers, "" when it is off.
func (d *Daemon) KKDCPAddr() string {
	if d.kkLn == nil {
		return ""
	}
	return d.kkLn.Addr().String()
}

// Shutdown stops accepting, drops what is being served and waits for it, at
// most until ctx is done.
func (d *Daemon) Shutdown(ctx context.Context) error {
	var err error
	d.once.Do(func() {
		if d.mintSrv != nil {
			err = d.mintSrv.Shutdown(ctx)
			if err != nil {
				d.mintSrv.Close()
			}
		}
		if d.kkSrv != nil {
			if kerr := d.kkSrv.Shutdown(ctx); kerr != nil {
				d.kkSrv.Close()
				if err == nil {
					err = kerr
				}
			}
		}
		d.srv.Close()
		// The library closes the sockets it is serving, but a serving
		// goroutine that has not started yet has not told it about its socket
		// (it returns ErrClosed and leaves the socket open). Closing here,
		// idempotently, is what frees the port in every ordering.
		d.tcp.Close()
		d.udp.Close()
		if d.mintLn != nil {
			d.mintLn.Close()
		}
		d.wg.Wait()
		if cerr := d.rt.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

// listenKDC opens one TCP listener and one UDP socket on the same address. A
// client tries UDP first and falls back to TCP at the same port (RFC 4120
// 7.2), so the two must agree; with port 0 the UDP port follows the TCP one,
// and a collision is retried.
func listenKDC(addr string) (net.Listener, net.PacketConn, error) {
	host, port, _ := net.SplitHostPort(addr)
	tries := 1
	if port == "0" {
		tries = 20
	}
	var last error
	for range tries {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("kdc listener %s: %w", addr, err)
		}
		udpAddr := addr
		if port == "0" {
			udpAddr = net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
		}
		pc, err := net.ListenPacket("udp", udpAddr)
		if err == nil {
			return ln, pc, nil
		}
		ln.Close()
		last = err
	}
	return nil, nil, fmt.Errorf("kdc udp socket %s: %w", addr, last)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
