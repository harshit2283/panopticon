// Ground-truth HTTPS traffic between Go processes, for scoring the agent's
// Go crypto/tls capture (score.py, same truth format as http_oracle.py).
//
//	go run tests/oracle/go_tls_oracle.go server ADDR
//	go run tests/oracle/go_tls_oracle.go client ADDR N OUT [SEED]
//
// HTTP/1.1 over TLS (HTTP/2 disabled on both sides; H2=1 in the environment
// negotiates HTTP/2 via ALPN instead, as Go does by default), keep-alive connections
// of up to 6 requests: GETs with 0 B to 70 KB bodies and POSTs whose JSON body
// carries an email and an SSN. The server uses an in-memory self-signed
// certificate; the client does not verify it. Build with symbols (the
// default) so the agent can find the crypto/tls functions it probes.
//
// By default each finished connection is closed before the next opens, so
// Go may allocate a new connection's *tls.Conn at a freed one's address:
// the agent's key for it is reused (a reused key never decodes again,
// docs/adr/ADR-014). REUSE=0 instead holds every connection open until the
// client exits, so no *tls.Conn address is reused within either process.
// Each truth record carries its client *tls.Conn address (tls_conn); the
// server writes each accepted one's address to $CONNLOG, one per line.
package main

import (
	"bytes"
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
	mrand "math/rand"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: go_tls_oracle server ADDR | client ADDR N OUT [SEED]")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2])
	case "client":
		client(os.Args[2:])
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oracle"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func server(addr string) {
	body := bytes.Repeat([]byte("x"), 1<<17)
	mux := http.NewServeMux()
	mux.HandleFunc("/len/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/len/"))
		if n < 0 || n > len(body) {
			n = 0
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(body[:n])
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	})
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{selfSigned()},
		},
	}
	if os.Getenv("H2") != "1" {
		// Non-nil, empty: no HTTP/2.
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	if path := os.Getenv("CONNLOG"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			log.Fatal(err)
		}
		var mu sync.Mutex
		srv.ConnState = func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				mu.Lock()
				fmt.Fprintf(f, "%p\n", c) // the *tls.Conn
				mu.Unlock()
			}
		}
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

type truth struct {
	ID           string   `json:"id"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	BodyPII      []string `json:"body_pii"`
	Status       int      `json:"status"`
	ResponseSize int      `json:"response_size"`
	Conn         int      `json:"conn"`
	Pos          int      `json:"pos"`
	TLSConn      string   `json:"tls_conn"`
}

func client(args []string) {
	addr, out := args[0], args[2]
	n, _ := strconv.Atoi(args[1])
	seed := int64(1234)
	if len(args) > 3 {
		seed, _ = strconv.ParseInt(args[3], 10, 64)
	}
	rnd := mrand.New(mrand.NewSource(seed))
	newClient := func() (*http.Client, *http.Transport) {
		tr := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 1,
		}
		if os.Getenv("H2") == "1" {
			tr.ForceAttemptHTTP2 = true
		} else {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}, tr
	}
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	hc, tr := newClient()
	reuse := os.Getenv("REUSE") != "0"
	held := []*http.Transport{tr}
	defer func() {
		for _, t := range held {
			t.CloseIdleConnections()
		}
	}()
	conn, pos := 0, -1
	for i := 0; i < n; i++ {
		if pos >= 5 || (pos >= 0 && rnd.Float64() < 0.15) {
			if reuse {
				tr.CloseIdleConnections()
				held = held[:0]
			}
			hc, tr = newClient()
			held = append(held, tr)
			conn, pos = conn+1, 0
		} else {
			pos++
		}
		tag := fmt.Sprintf("q%d", i)
		var req *http.Request
		var pii []string
		r := rnd.Float64()
		switch {
		case r < 0.6:
			size := []int{0, 10, 500, 1400, 3000, 9000, 70000}[rnd.Intn(7)]
			req, _ = http.NewRequest("GET", fmt.Sprintf("https://%s/len/%d?id=%s", addr, size, tag), nil)
		case r < 0.85:
			email, ssn := fmt.Sprintf("user%d@example.com", i), fmt.Sprintf("123-45-%04d", i%10000)
			body, _ := json.Marshal(map[string]string{"email": email, "ssn": ssn,
				"note": strings.Repeat("p", []int{5, 800, 5000}[rnd.Intn(3)])})
			req, _ = http.NewRequest("POST", fmt.Sprintf("https://%s/submit?id=%s", addr, tag), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			pii = []string{email, ssn}
		default:
			req, _ = http.NewRequest("GET", fmt.Sprintf("https://%s/missing?id=%s", addr, tag), nil)
		}
		var tlsConn string
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { tlsConn = fmt.Sprintf("%p", info.Conn) },
		}))
		resp, err := hc.Do(req)
		if err != nil {
			log.Fatalf("request %s: %v", tag, err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if pii == nil {
			pii = []string{}
		}
		enc.Encode(truth{ID: tag, Method: req.Method, Path: req.URL.RequestURI(), BodyPII: pii,
			Status: resp.StatusCode, ResponseSize: len(data), Conn: conn, Pos: pos, TLSConn: tlsConn})
	}
	fmt.Fprintf(os.Stderr, "go-tls: %d requests\n", n)
}
