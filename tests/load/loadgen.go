// HTTP/1.1 load generator and server for agent scalability tests.
//
//	go run tests/load/loadgen.go server -addr 10.99.0.1:18090
//	go run tests/load/loadgen.go client -url http://10.99.0.1:18090 -c 64 -d 20s \
//	    [-rate 0] [-newconn] [-size 512] [-post 0.2] -out ids.txt
//
// The client runs -c workers for -d, each issuing requests back to back
// (or paced to a total of -rate req/s). Every completed request's id is
// written to -out, one per line, so score_load.py can compute capture recall
// at that load. -newconn opens a fresh TCP connection per request
// (Connection: close), which stresses connection tracking instead of
// parsing; -fin does the same without the header, closing each connection
// with a plain FIN like connection pools and database drivers do. A fraction -post of the
// requests are POSTs whose JSON body carries an email address.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: loadgen server|client [flags]")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:18090", "listen address")
	fs.Parse(args)
	body := bytes.Repeat([]byte("x"), 1<<20)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/len/"))
		if n < 0 || n > len(body) {
			n = 0
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(body[:n])
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:18090", "server base URL")
	conc := fs.Int("c", 64, "concurrent workers")
	dur := fs.Duration("d", 20*time.Second, "test duration")
	rate := fs.Int("rate", 0, "total requests/s (0 = as fast as possible)")
	newConn := fs.Bool("newconn", false, "new TCP connection per request (Connection: close)")
	fin := fs.Bool("fin", false, "keep-alive requests, but close each connection (FIN) after its response")
	size := fs.Int("size", 512, "response body size")
	post := fs.Float64("post", 0.2, "fraction of POST requests")
	out := fs.String("out", "ids.txt", "file of completed request ids")
	fs.Parse(args)

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	var mu sync.Mutex
	var done, failed atomic.Int64
	var next atomic.Int64

	var tick <-chan time.Time
	if *rate > 0 {
		t := time.NewTicker(time.Second / time.Duration(*rate))
		defer t.Stop()
		tick = t.C
	}
	deadline := time.Now().Add(*dur)
	postEvery := 0
	if *post > 0 {
		postEvery = int(1 / *post)
	}

	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{
				DisableKeepAlives:   *newConn,
				MaxIdleConnsPerHost: 1,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			}
			hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			for time.Now().Before(deadline) {
				if tick != nil {
					<-tick
				}
				id := next.Add(1)
				tok := fmt.Sprintf("r%d", id)
				var req *http.Request
				if postEvery > 0 && id%int64(postEvery) == 0 {
					body := fmt.Sprintf(`{"id":%q,"email":"user%d@example.com"}`, tok, id)
					req, _ = http.NewRequest("POST", fmt.Sprintf("%s/len/%d?id=%s", *url, *size, tok), strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req, _ = http.NewRequest("GET", fmt.Sprintf("%s/len/%d?id=%s", *url, *size, tok), nil)
				}
				resp, err := hc.Do(req)
				if err != nil {
					failed.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if *fin {
					tr.CloseIdleConnections()
				}
				done.Add(1)
				mu.Lock()
				w.WriteString(tok)
				w.WriteByte('\n')
				mu.Unlock()
			}
			tr.CloseIdleConnections()
		}()
	}
	start := time.Now()
	wg.Wait()
	elapsed := time.Since(start)
	w.Flush()
	f.Close()
	fmt.Printf("requests=%d failed=%d elapsed=%.1fs rate=%.0f/s\n",
		done.Load(), failed.Load(), elapsed.Seconds(), float64(done.Load())/elapsed.Seconds())
}
