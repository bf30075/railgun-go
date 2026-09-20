package broadcaster

import (
	"encoding/json"
	"sync"
)

// TransactResponseStore holds the pending decrypted broadcaster reply.
type TransactResponseStore struct {
	mu       sync.Mutex
	sharedKey []byte
	response *TransactResponse
}

func NewTransactResponseStore() *TransactResponseStore {
	return &TransactResponseStore{}
}

func (s *TransactResponseStore) SetSharedKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sharedKey = append([]byte{}, key...)
	s.response = nil
}

func (s *TransactResponseStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sharedKey = nil
	s.response = nil
}

func (s *TransactResponseStore) Get() (TransactResponse, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.response == nil {
		return TransactResponse{}, false
	}
	return *s.response, true
}

func (s *TransactResponseStore) HandleMessage(msg Message, dbg Debugger) {
	if dbg == nil {
		dbg = nopDebugger{}
	}
	s.mu.Lock()
	sharedKey := append([]byte{}, s.sharedKey...)
	s.mu.Unlock()
	if len(sharedKey) == 0 || len(msg.Payload) == 0 {
		return
	}
	dbg.Log("Transact Response received.")
	var envelope struct {
		Result EncryptedData `json:"result"`
	}
	if err := json.Unmarshal(msg.Payload, &envelope); err != nil {
		return
	}
	decrypted, ok := DecryptAESGCM256(envelope.Result, sharedKey)
	if !ok {
		return
	}
	raw, err := json.Marshal(decrypted)
	if err != nil {
		return
	}
	var resp TransactResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return
	}
	s.mu.Lock()
	s.response = &resp
	s.mu.Unlock()
}
