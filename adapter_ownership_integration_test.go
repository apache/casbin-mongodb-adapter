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
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/persist"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Integration tests require explicit configuration and use only unique databases.
func ownershipIntegrationDatabase(t *testing.T) (string, *mongo.Database) {
	t.Helper()
	uri := os.Getenv("TEST_MONGODB_URL")
	if uri == "" {
		t.Skip("set TEST_MONGODB_URL to an isolated MongoDB test server")
	}
	if !strings.HasPrefix(uri, "mongodb://") && !strings.HasPrefix(uri, "mongodb+srv://") {
		uri = "mongodb://" + uri
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal("invalid TEST_MONGODB_URL")
	}
	name := "casbin_ownership_" + bson.NewObjectID().Hex()
	parsed.Path = "/" + name
	query := parsed.Query()
	query.Set("serverSelectionTimeoutMS", "5000")
	query.Set("timeoutMS", "5000")
	parsed.RawQuery = query.Encode()
	uri = parsed.String()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database(name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.Drop(ctx); err != nil {
			t.Error(err)
		}
		if err := client.Disconnect(ctx); err != nil && !errors.Is(err, mongo.ErrClientDisconnected) {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated database: %s", name)
	return uri, db
}

func newOwnershipIntegrationClient(t *testing.T, uri string) *mongo.Client {
	t.Helper()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Disconnect(ctx); err != nil && !errors.Is(err, mongo.ErrClientDisconnected) {
			t.Error(err)
		}
	})
	return client
}

func TestClientOwnershipByDBIntegration(t *testing.T) {
	for _, tc := range []struct {
		name string
		owns bool
	}{{"borrowed by default", false}, {"explicit ownership", true}} {
		t.Run(tc.name, func(t *testing.T) {
			uri, db := ownershipIntegrationDatabase(t)
			client := newOwnershipIntegrationClient(t, uri)
			config := &AdapterConfig{DatabaseName: db.Name(), CollectionName: "policies"}
			if tc.owns {
				config.OwnsClient = true
			}
			value, err := NewAdapterByDB(client, config)
			if err != nil {
				t.Fatal(err)
			}
			a := value.(*adapter)
			if a.client != client || a.collection.Database().Client() != client {
				t.Fatal("constructor did not reuse supplied client")
			}
			if a.collection.Database().Name() != db.Name() || a.collection.Name() != "policies" {
				t.Fatal("constructor changed database or collection")
			}
			application := client.Database(db.Name()).Collection("application")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := application.InsertOne(ctx, bson.D{{Key: "beforeCleanup", Value: true}}); err != nil {
				t.Fatal(err)
			}
			finalizer(a)
			_, err = application.InsertOne(ctx, bson.D{{Key: "afterCleanup", Value: true}})
			if tc.owns {
				if !errors.Is(err, mongo.ErrClientDisconnected) {
					t.Fatalf("expected disconnected owned client, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("borrowed client is no longer usable: %v", err)
			}
		})
	}
}

func TestClientOwnershipByDBIndexFailureIntegration(t *testing.T) {
	uri, db := ownershipIntegrationDatabase(t)
	client := newOwnershipIntegrationClient(t, uri)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	duplicate := CasbinRule{PType: "p", V0: "alice", V1: "resource", V2: "read"}
	if _, err := db.Collection("policies").InsertMany(ctx, []interface{}{duplicate, duplicate}); err != nil {
		t.Fatal(err)
	}
	a, err := NewAdapterByDB(client, &AdapterConfig{DatabaseName: db.Name(), CollectionName: "policies"})
	if !mongo.IsDuplicateKeyError(err) || a != nil {
		t.Fatalf("expected unique-index initialization failure, got %v, %v", a, err)
	}
	if _, err := client.Database(db.Name()).Collection("application").InsertOne(ctx, bson.D{{Key: "afterFailure", Value: true}}); err != nil {
		t.Fatalf("borrowed client is no longer usable: %v", err)
	}
}

func TestClientOwnershipCreatedConstructorsIntegration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func(string, string) (persist.Adapter, error)
	}{
		{"URI", func(uri, _ string) (persist.Adapter, error) { return NewAdapter(uri) }},
		{"client options", func(uri, db string) (persist.Adapter, error) {
			return NewAdapterWithClientOption(options.Client().ApplyURI(uri), db)
		}},
		{"collection name", func(uri, db string) (persist.Adapter, error) {
			return NewAdapterWithCollectionName(options.Client().ApplyURI(uri), db, "policies")
		}},
		{"filtered", func(uri, _ string) (persist.Adapter, error) { return NewFilteredAdapter(uri) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uri, db := ownershipIntegrationDatabase(t)
			value, err := tc.create(uri, db.Name())
			if err != nil {
				t.Fatal(err)
			}
			a := value.(*adapter)
			if a.collection.Database().Name() != db.Name() {
				t.Fatal("constructor used a different database")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.client.Ping(ctx, nil); err != nil {
				t.Fatal(err)
			}
			finalizer(a)
			if err := a.client.Ping(ctx, nil); !errors.Is(err, mongo.ErrClientDisconnected) {
				t.Fatalf("expected internally created client to be disconnected, got %v", err)
			}
		})
	}
}
