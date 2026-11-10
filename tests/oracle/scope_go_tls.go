// Marker traffic over Go crypto/tls for the scope lab tests (run_scope.sh),
// the Go counterpart of scope_traffic.py: same markers, same truth lines.
//
//	scope_go_tls server ADDR
//	scope_go_tls client ADDR TAG N OUT
//
// Environment: CGROUP (+ CG_ROOT), GO, EVERY, GAP as in scope_traffic.py.
// Build with symbols (the default) so the agent finds crypto/tls.
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
	"strconv"
	"strings"
	"time"
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

func main() {
	a := os.Args
	switch {
	case len(a) == 3 && a[1] == "server":
		server(a[2])
	case len(a) == 6 && a[1] == "client":
		n, _ := strconv.Atoi(a[4])
		client(a[2], a[3], n, a[5])
	default:
		log.Fatal("usage: scope_go_tls server ADDR | client ADDR TAG N OUT")
	}
}
