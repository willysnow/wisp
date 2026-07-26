package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

const (
	// queueSize is how many events may be waiting for delivery. Beyond this,
	// events are dropped rather than queued.
	queueSize = 4096

	// batchSize and flushInterval trade delivery latency against request count.
	// A honeypot is low-volume by nature, so the interval matters more.
	batchSize     = 200
	flushInterval = 5 * time.Second

	// maxRetries per batch before it is discarded. Retrying forever would let a
	// dead console back-pressure into an unbounded memory leak.
	maxRetries = 3
)

// Remote delivers events to a wisp console over HTTP.
//
// Emit never blocks and never fails: a honeypot service goroutine must not be
// held up — or worse, hung — because the console is slow or down. When the
// queue is full, events are dropped and counted. Losing telemetry is bad;
// having the sensor stop answering the network because its reporting channel
// stalled is far worse, because a hung service is a detectable tell.
type Remote struct {
	url    string
	token  string
	client *http.Client

	queue chan event.Event
	done  chan struct{}
	wg    sync.WaitGroup

	mu      sync.Mutex
	dropped int64
}

// RemoteOptions configures delivery to a console.
type RemoteOptions struct {
	// URL is the console's base address and Token authenticates this sensor.
	URL   string
	Token string

	// TLS, when set, replaces the default transport's settings — this is how a
	// sensor trusts a console with a private certificate. nil means system
	// roots.
	TLS *tls.Config
}

// NewRemote starts the delivery loop. Call Close to flush and stop.
func NewRemote(opts RemoteOptions) *Remote {
	client := &http.Client{Timeout: 30 * time.Second}
	if opts.TLS != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = opts.TLS
		client.Transport = transport
	}

	r := &Remote{
		url:    opts.URL + "/api/v1/events",
		token:  opts.Token,
		client: client,
		queue:  make(chan event.Event, queueSize),
		done:   make(chan struct{}),
	}
	r.wg.Add(1)
	go r.run()
	return r
}

func (r *Remote) Emit(e event.Event) {
	select {
	case r.queue <- e:
	default:
		r.mu.Lock()
		r.dropped++
		r.mu.Unlock()
	}
}

// Dropped reports how many events were discarded because the queue was full.
// Non-zero means the console has been unreachable or too slow.
func (r *Remote) Dropped() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// Close stops the delivery loop after one final flush attempt.
func (r *Remote) Close() {
	close(r.done)
	r.wg.Wait()
}

func (r *Remote) run() {
	defer r.wg.Done()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]event.Event, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.deliver(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e := <-r.queue:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-r.done:
			// Drain whatever is queued so a clean shutdown does not lose the
			// events that prompted it.
			for {
				select {
				case e := <-r.queue:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func (r *Remote) deliver(batch []event.Event) {
	body, err := json.Marshal(batch)
	if err != nil {
		return
	}

	backoff := time.Second
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-r.done:
				return // shutting down; do not keep retrying
			}
			backoff *= 2
		}
		if err := r.post(body); err == nil {
			return
		}
	}

	r.mu.Lock()
	r.dropped += int64(len(batch))
	r.mu.Unlock()
}

func (r *Remote) post(body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("console returned %s", resp.Status)
	}
	return nil
}
