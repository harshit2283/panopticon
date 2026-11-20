// Marker traffic over Go crypto/tls for the scope lab tests (run_scope.sh),
// the Go counterpart of scope_traffic.py: same markers, same truth lines.
//
//	scope_go_tls server ADDR
//	scope_go_tls client ADDR TAG N OUT
//
// Environment: CGROUP (+ CG_ROOT), GO, EVERY, GAP as in scope_traffic.py.
// Build with symbols (the default) so the agent finds crypto/tls.
//
// Go TLS read fixtures for the scope_attach lab test (go_tls_reads):
//
//	scope_go_tls rserver ADDR        echo server reading into a stack buffer
//	scope_go_tls rclient ADDR TAG N  N one-message connections, 8 at a time
//	scope_go_tls rhold ADDR K        K connections blocked in Read, forever
//	scope_go_tls rslow ADDR TAG FILE PRE, then POST once FILE exists
//
// Their client side speaks TLS 1.3, or TLS 1.2 with TLS12=aead (default
// suites) or TLS12=cbc (ECDHE-ECDSA AES-128-CBC-SHA).
//
// rserver grows each connection goroutine's stack before every Read into a
// stack array and runs the GC every millisecond, which shrinks (copies) the
// stack of a goroutine parked in Read; its reply says whether the buffer
// moved during that Read (" m=1"). Messages are B2R-TAG-i (rclient) or
// B2R-TAG-PRE / -POST (rslow); replies are "ECHO <message> m=0|1".
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// prepare joins CGROUP, then waits for GO, before any socket exists.
func prepare() {
	if cg := os.Getenv("CGROUP"); cg != "" {
		p := filepath.Join(env("CG_ROOT", "/sys/fs/cgroup"), cg, "cgroup.procs")
		if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			log.Fatal(err)
		}
	}
	for g := os.Getenv("GO"); g != ""; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(g); err == nil {
			break
		}
	}
}

func cert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "b2"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func server(addr string) {
	prepare()
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert()}})
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReader(c)
			for {
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				body, _ := io.ReadAll(req.Body)
				out := append([]byte("RESP "), body...)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(out), out)
			}
		}(c)
	}
}

func client(addr, tag string, n int, out string) {
	prepare()
	every, _ := strconv.Atoi(env("EVERY", "5"))
	gap, _ := strconv.ParseFloat(env("GAP", "0.05"), 64)
	f, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	var c *tls.Conn
	var r *bufio.Reader
	for i := 0; n == 0 || i < n; {
		if c == nil || i%every == 0 {
			if c != nil {
				c.Close()
			}
			c, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				log.Print(err)
				c = nil
				time.Sleep(time.Duration(gap * float64(time.Second)))
				continue
			}
			r = bufio.NewReader(c)
		}
		m := fmt.Sprintf("B2M-%s-%d", tag, i)
		t := float64(time.Now().UnixNano()) / 1e9
		body := "mark=" + m + "&contact=" + strings.ToLower(m) + "@example.com"
		fmt.Fprintf(c, "POST /%s HTTP/1.1\r\nHost: b2\r\nX-Mark: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			m, m, len(body), body)
		resp, err := http.ReadResponse(r, nil)
		if err == nil {
			var b []byte
			b, err = io.ReadAll(resp.Body)
			if err == nil && !strings.Contains(string(b), m) {
				err = fmt.Errorf("bad response")
			}
		}
		if err != nil {
			log.Print(err)
			c = nil
			continue
		}
		la, ra := c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr)
		line, _ := json.Marshal(map[string]any{"m": m, "t": t, "laddr": la.IP.String(), "lport": la.Port,
			"raddr": ra.IP.String(), "rport": ra.Port, "pid": os.Getpid()})
		f.Write(append(line, '\n'))
		i++
		time.Sleep(time.Duration(gap * float64(time.Second)))
	}
}

// grow uses about n KiB of stack, then returns it.
//
//go:noinline
func grow(n int) byte {
	var pad [1024]byte
	pad[n%1024] = byte(n)
	if n == 0 {
		return pad[0]
	}
	return grow(n-1) + pad[n%1024]
}

func rserver(addr string) {
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert()}})
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			runtime.GC()
			time.Sleep(time.Millisecond)
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c *tls.Conn) {
			defer c.Close()
			for {
				grow(256)
				var buf [512]byte // stays on the stack: (*Conn).Read does not keep b
				for i := range buf {
					buf[i] = 'x'
				}
				before := uintptr(unsafe.Pointer(&buf[0]))
				n, err := c.Read(buf[:])
				if err != nil {
					return
				}
				m := 0
				if uintptr(unsafe.Pointer(&buf[0])) != before {
					m = 1
				}
				msg := string(buf[:n]) // a copy: buf itself must not escape
				if _, err := fmt.Fprintf(c, "ECHO %s m=%d", msg, m); err != nil {
					return
				}
			}
		}(c.(*tls.Conn))
	}
}

var sink [][]byte // read buffers escape: client reads go to the heap

func exchange(c *tls.Conn, msg string) {
	if _, err := c.Write([]byte(msg)); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 512)
	sink = append(sink[:0], buf)
	n, err := c.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "ECHO "+msg+" m=") {
		log.Fatalf("%s: %q %v", msg, buf[:n], err)
	}
}

// dial connects with TLS 1.3, or TLS 1.2 when TLS12 is "aead" (the
// default suites) or "cbc" (AES-CBC with HMAC, decrypted differently).
func dial(addr string) *tls.Conn {
	cfg := &tls.Config{InsecureSkipVerify: true}
	tls12 := os.Getenv("TLS12")
	switch tls12 {
	case "":
	case "aead":
		cfg.MaxVersion = tls.VersionTLS12
	case "cbc":
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	default:
		log.Fatalf("TLS12=%q: aead or cbc", tls12)
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	st := c.ConnectionState()
	if tls12 != "" && (st.Version != tls.VersionTLS12 ||
		(tls12 == "cbc") != (st.CipherSuite == tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
		log.Fatalf("TLS12=%s: negotiated %x %x", tls12, st.Version, st.CipherSuite)
	}
	return c
}

func rclient(addr, tag string, n int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) { // one goroutine per connection: goroutines churn
			defer wg.Done()
			defer func() { <-sem }()
			c := dial(addr)
			defer c.Close()
			time.Sleep(20 * time.Millisecond) // the server parks in Read
			exchange(c, fmt.Sprintf("B2R-%s-%d", tag, i))
		}(i)
	}
	wg.Wait()
}

func rhold(addr string, k int) {
	for i := 0; i < k; i++ {
		c := dial(addr)
		go func() {
			var b [64]byte
			c.Read(b[:])
		}()
	}
	select {}
}

func rslow(addr, tag, file string) {
	c := dial(addr)
	defer c.Close()
	exchange(c, "B2R-"+tag+"-PRE")
	for {
		if _, err := os.Stat(file); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	exchange(c, "B2R-"+tag+"-POST")
}

func main() {
	a := os.Args
	switch {
	case len(a) == 3 && a[1] == "rserver":
		rserver(a[2])
	case len(a) == 5 && a[1] == "rclient":
		n, _ := strconv.Atoi(a[4])
		rclient(a[2], a[3], n)
	case len(a) == 4 && a[1] == "rhold":
		k, _ := strconv.Atoi(a[3])
		rhold(a[2], k)
	case len(a) == 5 && a[1] == "rslow":
		rslow(a[2], a[3], a[4])
	case len(a) == 3 && a[1] == "server":
		server(a[2])
	case len(a) == 6 && a[1] == "client":
		n, _ := strconv.Atoi(a[4])
		client(a[2], a[3], n, a[5])
	default:
		log.Fatal("usage: scope_go_tls server ADDR | client ADDR TAG N OUT | rserver ADDR | rclient ADDR TAG N | rhold ADDR K | rslow ADDR TAG FILE")
	}
}
