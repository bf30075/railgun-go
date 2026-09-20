package broadcaster

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/waku-org/go-waku/waku/v2/dnsdisc"
	"github.com/waku-org/go-waku/waku/v2/node"
	"github.com/waku-org/go-waku/waku/v2/peerstore"
	"github.com/waku-org/go-waku/waku/v2/protocol"
	"github.com/waku-org/go-waku/waku/v2/protocol/filter"
	"github.com/waku-org/go-waku/waku/v2/protocol/lightpush"
	"github.com/waku-org/go-waku/waku/v2/protocol/pb"
	"github.com/waku-org/go-waku/waku/v2/protocol/store"
	"github.com/waku-org/go-waku/waku/v2/protocol/subscription"
)

// WakuTransport is the live go-waku light-client transport.
type WakuTransport struct {
	cfg *Config
	dbg Debugger

	mu        sync.Mutex
	node      *node.WakuNode
	started   bool
	hasError  bool
	pubsub    string
	cancel    context.CancelFunc
	subs      []*filterSubscription
	handlers  map[string][]MessageHandler
}

type filterSubscription struct {
	contentTopic string
	cancel       func()
}

// NewWakuTransport builds a transport that dials the Railgun Waku mesh.
func NewWakuTransport(cfg *Config, dbg Debugger) (*WakuTransport, error) {
	if dbg == nil {
		dbg = nopDebugger{}
	}
	return &WakuTransport{
		cfg:      cfg,
		dbg:      dbg,
		pubsub:   cfg.PubSubTopic,
		handlers: map[string][]MessageHandler{},
	}, nil
}

func (t *WakuTransport) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started && t.node != nil {
		return nil
	}

	hostAddr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	if err != nil {
		t.hasError = true
		return err
	}

	opts := []node.WakuNodeOption{
		node.WithHostAddress(hostAddr),
		node.WithClusterID(t.cfg.ClusterID),
		node.WithShards([]uint16{t.cfg.ShardID}),
		node.WithPubSubTopics([]string{t.cfg.PubSubTopic}),
		node.WithWakuFilterLightNode(),
		node.WithLightPush(),
		node.WithWakuStore(),
		node.WithMaxPeerConnections(5),
		node.WithWebsockets("0.0.0.0", 0),
	}

	wakuNode, err := node.New(opts...)
	if err != nil {
		t.hasError = true
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	if err := wakuNode.Start(runCtx); err != nil {
		cancel()
		t.hasError = true
		return err
	}

	t.node = wakuNode
	t.cancel = cancel
	t.started = true
	t.hasError = false
	t.pubsub = t.cfg.PubSubTopic

	go t.bootstrapPeers(runCtx)
	return nil
}

func (t *WakuTransport) bootstrapPeers(ctx context.Context) {
	peers := t.cfg.BootstrapPeers()
	for _, peerAddr := range peers {
		if err := t.node.DialPeer(ctx, peerAddr); err != nil {
			t.dbg.Log("dial bootstrap peer failed: " + peerAddr + ": " + err.Error())
		}
	}
	for _, enrURL := range t.cfg.DNSDiscoveryURLs() {
		nodes, err := dnsdisc.RetrieveNodes(ctx, enrURL)
		if err != nil {
			t.dbg.Log("dns discovery failed: " + err.Error())
			continue
		}
		for _, discovered := range nodes {
			if discovered.PeerInfo.ID == "" {
				continue
			}
			addrs := discovered.PeerInfo.Addrs
			if len(addrs) == 0 {
				continue
			}
			_, err := t.node.AddPeer(addrs, peerstore.Static, []string{t.pubsub},
				filter.FilterSubscribeID_v20beta1,
				lightpush.LightPushID_v20beta1,
				store.StoreQueryID_v300,
			)
			if err != nil {
				t.dbg.Log("add discovered peer failed: " + err.Error())
				continue
			}
			_ = t.node.DialPeerByID(ctx, discovered.PeerInfo.ID)
		}
	}
}

func (t *WakuTransport) Stop(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sub := range t.subs {
		if sub.cancel != nil {
			sub.cancel()
		}
	}
	t.subs = nil
	t.handlers = map[string][]MessageHandler{}
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	if t.node != nil {
		t.node.Stop()
		t.node = nil
	}
	t.started = false
	return nil
}

func (t *WakuTransport) Started() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.started && t.node != nil
}

func (t *WakuTransport) HasError() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hasError
}

func (t *WakuTransport) PeerCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.node == nil {
		return 0
	}
	return t.node.PeerCount()
}

func (t *WakuTransport) Subscribe(ctx context.Context, contentTopic string, handler MessageHandler) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.node == nil || t.node.FilterLightnode() == nil {
		return fmt.Errorf("waku filter light node is not available")
	}
	t.handlers[contentTopic] = append(t.handlers[contentTopic], handler)

	contentFilter := protocol.ContentFilter{
		PubsubTopic:   t.pubsub,
		ContentTopics: protocol.NewContentTopicSet(contentTopic),
	}
	subs, err := t.node.FilterLightnode().Subscribe(ctx, contentFilter)
	if err != nil {
		return err
	}
	subCtx, cancel := context.WithCancel(context.Background())
	t.subs = append(t.subs, &filterSubscription{contentTopic: contentTopic, cancel: cancel})
	for _, sub := range subs {
		go t.consumeFilter(subCtx, contentTopic, sub)
	}
	return nil
}

func (t *WakuTransport) consumeFilter(ctx context.Context, contentTopic string, sub *subscription.SubscriptionDetails) {
	for {
		select {
		case <-ctx.Done():
			return
		case env, ok := <-sub.C:
			if !ok {
				return
			}
			if env == nil || env.Message() == nil {
				continue
			}
			msg := Message{
				Payload:      append([]byte{}, env.Message().Payload...),
				ContentTopic: contentTopic,
				TimestampMS:  env.Message().GetTimestamp() / int64(time.Millisecond/time.Nanosecond),
			}
			if msg.TimestampMS == 0 {
				msg.TimestampMS = timeNowMS()
			}
			t.mu.Lock()
			handlers := append([]MessageHandler{}, t.handlers[contentTopic]...)
			t.mu.Unlock()
			for _, handler := range handlers {
				handler(msg)
			}
		}
	}
}

func (t *WakuTransport) UnsubscribeAll(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sub := range t.subs {
		if sub.cancel != nil {
			sub.cancel()
		}
	}
	t.subs = nil
	t.handlers = map[string][]MessageHandler{}
	if t.node != nil && t.node.FilterLightnode() != nil {
		_, _ = t.node.FilterLightnode().UnsubscribeAll(context.Background())
	}
	return nil
}

func (t *WakuTransport) Publish(ctx context.Context, contentTopic string, payload []byte) error {
	t.mu.Lock()
	wakuNode := t.node
	pubsub := t.pubsub
	t.mu.Unlock()
	if wakuNode == nil || wakuNode.Lightpush() == nil {
		return fmt.Errorf("waku lightpush is not available")
	}
	msg := &pb.WakuMessage{
		Payload:      payload,
		ContentTopic: contentTopic,
		Timestamp:    protoInt64(time.Now().UnixNano()),
	}
	_, err := wakuNode.Lightpush().Publish(ctx, msg, lightpush.WithPubSubTopic(pubsub))
	return err
}

func (t *WakuTransport) QueryStore(ctx context.Context, contentTopic string, lookbackMS int64, handler MessageHandler) error {
	t.mu.Lock()
	wakuNode := t.node
	pubsub := t.pubsub
	t.mu.Unlock()
	if wakuNode == nil || wakuNode.Store() == nil {
		return nil
	}
	end := time.Now()
	start := end.Add(-time.Duration(lookbackMS) * time.Millisecond)
	startNS := start.UnixNano()
	endNS := end.UnixNano()
	criteria := store.FilterCriteria{
		ContentFilter: protocol.NewContentFilter(pubsub, contentTopic),
		TimeStart:     &startNS,
		TimeEnd:       &endNS,
	}
	response, err := wakuNode.Store().Query(ctx, criteria)
	if err != nil {
		t.dbg.Log("store query failed: " + err.Error())
		return nil
	}
	for _, item := range response.Messages() {
		if item == nil || item.GetMessage() == nil {
			continue
		}
		msg := item.GetMessage()
		handler(Message{
			Payload:      append([]byte{}, msg.Payload...),
			ContentTopic: contentTopic,
			TimestampMS:  msg.GetTimestamp() / int64(time.Millisecond/time.Nanosecond),
		})
	}
	return nil
}

func protoInt64(v int64) *int64 { return &v }
