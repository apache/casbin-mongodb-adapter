// Copyright 2026 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type ownershipBlockedDialer struct{}

func (ownershipBlockedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("network disabled in ownership unit test")
}

func ownershipClientOptions() *options.ClientOptions {
	return options.Client().SetHosts([]string{"ownership.invalid:27017"}).
		SetDialer(ownershipBlockedDialer{}).SetServerSelectionTimeout(10 * time.Millisecond)
}

func newOwnershipUnitClient(t *testing.T) *mongo.Client {
	t.Helper()
	client, err := mongo.Connect(ownershipClientOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := client.Disconnect(ctx); err != nil && !errors.Is(err, mongo.ErrClientDisconnected) {
			t.Error(err)
		}
	})
	return client
}

// This checks logical client state without opening a network connection.
func assertOwnershipClientState(t *testing.T, client *mongo.Client, disconnected bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := client.Ping(ctx, nil)
	if got := errors.Is(err, mongo.ErrClientDisconnected); got != disconnected {
		t.Fatalf("client disconnected = %v, want %v (ping error: %v)", got, disconnected, err)
	}
}

func TestClientOwnershipBorrowedCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cleanup func(*adapter)
	}{
		{"finalizer", finalizer},
		{"close", (*adapter).close},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newOwnershipUnitClient(t)
			a := &adapter{client: client, timeout: time.Second}
			tc.cleanup(a)
			assertOwnershipClientState(t, client, false)
		})
	}
}

func TestClientOwnershipOwnedCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cleanup func(*adapter)
	}{
		{"finalizer", finalizer},
		{"close", (*adapter).close},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newOwnershipUnitClient(t)
			a := &adapter{client: client, ownsClient: true, timeout: time.Second}
			tc.cleanup(a)
			assertOwnershipClientState(t, client, true)
		})
	}
}

func TestClientOwnershipByDBInitializationError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *AdapterConfig
	}{
		{"nil config", nil},
		{"default config", &AdapterConfig{}},
		{"explicit borrowed", &AdapterConfig{OwnsClient: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newOwnershipUnitClient(t)
			a, err := NewAdapterByDB(client, tc.config)
			if err == nil || a != nil {
				t.Fatalf("expected initialization failure with no adapter, got %v, %v", a, err)
			}
			assertOwnershipClientState(t, client, false)
		})
	}
}

func TestClientOwnershipInternallyCreatedOnInitializationError(t *testing.T) {
	a := &adapter{timeout: time.Second}
	err := a.open(ownershipClientOptions(), "ownership", "policies")
	if err == nil || a.client == nil {
		t.Fatalf("expected index initialization failure after client creation, got %v", err)
	}
	t.Cleanup(func() { _ = a.client.Disconnect(context.Background()) })
	if !a.ownsClient {
		t.Error("internally created client must belong to the adapter")
	}
	finalizer(a)
	assertOwnershipClientState(t, a.client, true)
}
