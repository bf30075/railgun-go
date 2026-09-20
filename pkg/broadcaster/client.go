package broadcaster

import (
	"context"
	"fmt"
	"sync"
	"time"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

// Client is an instance-oriented port of WakuBroadcasterClient.
type Client struct {
	mu sync.Mutex

	cfg           *Config
	dbg           Debugger
	transport     Transport
	cache         *FeeCache
	filter        *AddressFilter
	responses     *TransactResponseStore
	statusCB      StatusCallback
	nullifierLook NullifierTxidLookup

	chain         railchain.Chain
	started       bool
	restarting    bool
	contentTopics []string
	cancelPoll    context.CancelFunc
	pollDelay     time.Duration
}

// NewClient builds a broadcaster client. If Options.Transport is nil, a live
// Waku transport is created via NewWakuTransport.
func NewClient(opts Options) (*Client, error) {
	if len(opts.TrustedFeeSigner) == 0 {
		opts.TrustedFeeSigner = append([]string{}, DefaultTrustedFeeSigners...)
	}
	dbg := opts.Debugger
	if dbg == nil {
		dbg = nopDebugger{}
	}
	cfg := newConfig(opts)
	transport := opts.Transport
	if transport == nil {
		wt, err := NewWakuTransport(cfg, dbg)
		if err != nil {
			return nil, err
		}
		transport = wt
	}
	poiKeys := opts.POIActiveListKeys
	if poiKeys == nil {
		poiKeys = []string{}
	}
	return &Client{
		cfg:           cfg,
		dbg:           dbg,
		transport:     transport,
		cache:         NewFeeCache(poiKeys),
		filter:        NewAddressFilter(),
		responses:     NewTransactResponseStore(),
		nullifierLook: opts.NullifierLookup,
		pollDelay:     3 * time.Second,
	}, nil
}

// Start connects to Waku and begins fee/response observers for chain.
func (c *Client) Start(ctx context.Context, chain railchain.Chain, statusCallback StatusCallback) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chain = chain
	c.statusCB = statusCallback
	if err := c.transport.Start(ctx); err != nil {
		return fmt.Errorf("cannot connect to Broadcaster network: %w", err)
	}
	if err := c.setObserversLocked(ctx, chain); err != nil {
		_ = c.transport.Stop(ctx)
		return err
	}
	c.started = true
	pollCtx, cancel := context.WithCancel(context.Background())
	c.cancelPoll = cancel
	go c.pollStatus(pollCtx)
	return nil
}

// Stop disconnects Waku and clears started state.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelPoll != nil {
		c.cancelPoll()
		c.cancelPoll = nil
	}
	_ = c.transport.UnsubscribeAll(ctx)
	err := c.transport.Stop(ctx)
	c.started = false
	c.emitStatusLocked()
	return err
}

func (c *Client) IsStarted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func (c *Client) SetChain(ctx context.Context, chain railchain.Chain) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	c.chain = chain
	if err := c.setObserversLocked(ctx, chain); err != nil {
		return err
	}
	c.emitStatusLocked()
	return nil
}

func (c *Client) ContentTopics() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.contentTopics...)
}

func (c *Client) PeerCount() int {
	return c.transport.PeerCount()
}

func (c *Client) FindBestBroadcaster(chain railchain.Chain, tokenAddress string, useRelayAdapt bool) (SelectedBroadcaster, bool) {
	if !c.IsStarted() {
		return SelectedBroadcaster{}, false
	}
	return FindBestBroadcaster(c.cache, c.filter, c.cfg, chain, tokenAddress, useRelayAdapt)
}

func (c *Client) FindBroadcastersForToken(chain railchain.Chain, tokenAddress string, useRelayAdapt bool) []SelectedBroadcaster {
	if !c.IsStarted() {
		return nil
	}
	return FindBroadcastersForToken(c.cache, c.filter, c.cfg, chain, tokenAddress, useRelayAdapt, false)
}

func (c *Client) FindAllBroadcastersForChain(chain railchain.Chain, useRelayAdapt bool) []SelectedBroadcaster {
	if !c.IsStarted() {
		return nil
	}
	return FindAllBroadcastersForChain(c.cache, c.filter, c.cfg, chain, useRelayAdapt)
}

func (c *Client) FindRandomBroadcasterForToken(chain railchain.Chain, tokenAddress string, useRelayAdapt bool, percentageThreshold int) (SelectedBroadcaster, bool) {
	if !c.IsStarted() {
		return SelectedBroadcaster{}, false
	}
	return FindRandomBroadcasterForToken(c.cache, c.filter, c.cfg, chain, tokenAddress, useRelayAdapt, percentageThreshold)
}

func (c *Client) SupportsToken(chain railchain.Chain, tokenAddress string, useRelayAdapt bool) bool {
	return c.cache.SupportsToken(chain, tokenAddress, useRelayAdapt, c.cfg, c.filter)
}

func (c *Client) SetAddressFilters(allowlist, blocklist []string) {
	c.filter.SetAllowlist(allowlist)
	c.filter.SetBlocklist(blocklist)
}

func (c *Client) Status(chain railchain.Chain) ConnectionStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return connectionStatus(chain, c.transport, c.cache, c.filter, c.cfg)
}

func (c *Client) TryReconnect(ctx context.Context) error {
	c.mu.Lock()
	chain := c.chain
	c.cache.Reset(chain)
	c.emitStatusLocked()
	c.mu.Unlock()
	return c.restart(ctx)
}

// CreateTransaction builds an encrypted broadcaster transaction using this client session.
func (c *Client) CreateTransaction(
	txidVersion string,
	to string,
	data string,
	broadcasterRailgunAddress string,
	broadcasterFeesID string,
	chain railchain.Chain,
	nullifiers []string,
	overallBatchMinGasPrice string,
	useRelayAdapt bool,
	preTransactionPOIs map[string]map[string]any,
) (*Transaction, error) {
	if !c.IsStarted() {
		return nil, fmt.Errorf("broadcaster client is not started")
	}
	return CreateTransaction(
		txidVersion,
		to,
		data,
		broadcasterRailgunAddress,
		broadcasterFeesID,
		chain,
		nullifiers,
		overallBatchMinGasPrice,
		useRelayAdapt,
		preTransactionPOIs,
		c.transport,
		c.responses,
		c.cfg,
		c.dbg,
		c.nullifierLook,
	)
}

func (c *Client) setObserversLocked(ctx context.Context, chain railchain.Chain) error {
	if err := c.transport.UnsubscribeAll(ctx); err != nil {
		return err
	}
	feesTopic := ContentTopicFees(chain)
	responseTopic := ContentTopicTransactResponse(chain)
	if err := c.transport.Subscribe(ctx, feesTopic, func(msg Message) {
		HandleFeesMessage(chain, msg, feesTopic, c.cache, c.cfg, c.dbg)
	}); err != nil {
		return err
	}
	if err := c.transport.Subscribe(ctx, responseTopic, func(msg Message) {
		c.responses.HandleMessage(msg, c.dbg)
	}); err != nil {
		return err
	}
	c.contentTopics = []string{feesTopic, responseTopic}
	_ = c.transport.QueryStore(ctx, feesTopic, int64(c.cfg.HistoricalLookBackMS), func(msg Message) {
		HandleFeesMessage(chain, msg, feesTopic, c.cache, c.cfg, c.dbg)
	})
	return nil
}

func (c *Client) pollStatus(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.pollDelay):
			c.mu.Lock()
			status := c.emitStatusLocked()
			c.mu.Unlock()
			if status == StatusDisconnected || status == StatusError {
				_ = c.restart(context.Background())
			}
		}
	}
}

func (c *Client) emitStatusLocked() ConnectionStatus {
	status := connectionStatus(c.chain, c.transport, c.cache, c.filter, c.cfg)
	if c.statusCB != nil {
		c.statusCB(c.chain, status)
	}
	return status
}

func (c *Client) restart(ctx context.Context) error {
	c.mu.Lock()
	if c.restarting || !c.started {
		c.mu.Unlock()
		return nil
	}
	c.restarting = true
	chain := c.chain
	c.mu.Unlock()

	c.dbg.Log("Restarting Waku...")
	_ = c.transport.Stop(ctx)
	c.cache.Reset(chain)
	err := c.transport.Start(ctx)
	if err == nil {
		c.mu.Lock()
		err = c.setObserversLocked(ctx, chain)
		c.mu.Unlock()
	}

	c.mu.Lock()
	c.restarting = false
	c.mu.Unlock()
	if err != nil {
		c.dbg.Error(fmt.Errorf("error reinitializing Waku Broadcaster Client: %w", err))
	}
	return err
}

// FeeCache exposes the live fee cache for advanced callers/tests.
func (c *Client) FeeCache() *FeeCache { return c.cache }
