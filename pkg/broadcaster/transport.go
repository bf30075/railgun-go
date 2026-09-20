package broadcaster

import (
	"context"
	"sync"
)

// MessageHandler receives decoded Waku messages for a content topic.
type MessageHandler func(msg Message)

// Transport abstracts the Waku light-client operations used by the TS core.
type Transport interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Started() bool
	HasError() bool
	PeerCount() int
	Subscribe(ctx context.Context, contentTopic string, handler MessageHandler) error
	UnsubscribeAll(ctx context.Context) error
	Publish(ctx context.Context, contentTopic string, payload []byte) error
	QueryStore(ctx context.Context, contentTopic string, lookbackMS int64, handler MessageHandler) error
}

// MemoryTransport is an in-process pub/sub used by unit tests.
type MemoryTransport struct {
	mu        sync.RWMutex
	started   bool
	hasError  bool
	handlers  map[string][]MessageHandler
	published []struct {
		Topic   string
		Payload []byte
	}
}

func NewMemoryTransport() *MemoryTransport {
	return &MemoryTransport{handlers: map[string][]MessageHandler{}}
}

func (t *MemoryTransport) Start(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.started = true
	t.hasError = false
	return nil
}

func (t *MemoryTransport) Stop(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.started = false
	t.handlers = map[string][]MessageHandler{}
	return nil
}

func (t *MemoryTransport) Started() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.started
}

func (t *MemoryTransport) HasError() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.hasError
}

func (t *MemoryTransport) SetError(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hasError = v
}

func (t *MemoryTransport) PeerCount() int {
	if t.Started() {
		return 1
	}
	return 0
}

func (t *MemoryTransport) Subscribe(_ context.Context, contentTopic string, handler MessageHandler) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[contentTopic] = append(t.handlers[contentTopic], handler)
	return nil
}

func (t *MemoryTransport) UnsubscribeAll(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers = map[string][]MessageHandler{}
	return nil
}

func (t *MemoryTransport) Publish(_ context.Context, contentTopic string, payload []byte) error {
	t.mu.Lock()
	handlers := append([]MessageHandler{}, t.handlers[contentTopic]...)
	t.published = append(t.published, struct {
		Topic   string
		Payload []byte
	}{Topic: contentTopic, Payload: append([]byte{}, payload...)})
	t.mu.Unlock()
	msg := Message{Payload: append([]byte{}, payload...), ContentTopic: contentTopic, TimestampMS: timeNowMS()}
	for _, handler := range handlers {
		handler(msg)
	}
	return nil
}

func (t *MemoryTransport) QueryStore(context.Context, string, int64, MessageHandler) error {
	return nil
}

func (t *MemoryTransport) Published() []struct {
	Topic   string
	Payload []byte
} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]struct {
		Topic   string
		Payload []byte
	}, len(t.published))
	copy(out, t.published)
	return out
}
