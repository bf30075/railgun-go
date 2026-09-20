// Package broadcaster is a Go port of @railgun-community/waku-broadcaster-client.
//
// It discovers public broadcasters over the Railgun Waku mesh, caches fee
// announcements, encrypts transact payloads, and submits them via lightpush.
//
// The protocol surface (topics, fees, selection, encryption, transaction
// retry) always builds. The live Waku transport is provided by NewWakuTransport
// and requires the network at runtime.
package broadcaster
