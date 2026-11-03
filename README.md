MongoDB Adapter
====

[![Build](https://github.com/apache/casbin-mongodb-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/apache/casbin-mongodb-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/apache/casbin-mongodb-adapter/badge.svg?branch=master)](https://coveralls.io/github/apache/casbin-mongodb-adapter?branch=master)
[![Godoc](https://godoc.org/github.com/apache/casbin-mongodb-adapter?status.svg)](https://pkg.go.dev/github.com/apache/casbin-mongodb-adapter/v4)
[![Release](https://img.shields.io/github/release/apache/casbin-mongodb-adapter.svg)](https://github.com/apache/casbin-mongodb-adapter/releases/latest)
[![License](https://img.shields.io/github/license/apache/casbin-mongodb-adapter)](https://github.com/apache/casbin-mongodb-adapter/blob/master/LICENSE)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

MongoDB Adapter is the [Mongo DB](https://www.mongodb.com) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from MongoDB or save policy to it.

## Installation

    go get -u github.com/apache/casbin-mongodb-adapter/v4

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v3"
	"github.com/apache/casbin-mongodb-adapter/v4"
)

func main() {
	// Initialize a MongoDB adapter and use it in a Casbin enforcer:
	// The adapter will use the database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a,err := mongodbadapter.NewAdapter("127.0.0.1:27017") // Your MongoDB URL. 
	if err != nil {
		panic(err)
	}
	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := mongodbadapter.NewAdapter("127.0.0.1:27017/abc")

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```
## Advanced Example

```go
package main

import (
	"github.com/casbin/casbin/v3"
	"github.com/apache/casbin-mongodb-adapter/v4"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// Initialize a MongoDB adapter with NewAdapterWithClientOption:
	// The adapter will use custom mongo client options.
	// custom database name.
	// default collection name 'casbin_rule'.
	mongoClientOption := mongooptions.Client().ApplyURI("mongodb://127.0.0.1:27017")
	databaseName := "casbin"
	a,err := mongodbadapter.NewAdapterWithClientOption(mongoClientOption, databaseName)
	// Or you can use NewAdapterWithCollectionName for custom collection name.
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Client ownership

`NewAdapterByDB` borrows the supplied `*mongo.Client` by default, including when
its configuration is nil. Adapter cleanup leaves that client open. The
application must call `client.Disconnect(ctx)` at shutdown, after all users of
that client have finished.

```go
// Reuse the application's existing client without transferring ownership.
a, err := mongodbadapter.NewAdapterByDB(client, &mongodbadapter.AdapterConfig{
    DatabaseName:   "my_app",
    CollectionName: "casbin_rule",
})
if err != nil {
    return err
}
// Use a with Casbin; the application still owns client.
```

Set `OwnsClient: true` to explicitly transfer ownership to the adapter. Its
finalizer may then disconnect the client once the adapter is no longer reachable;
use this only when other application components no longer need that client.

```go
a, err := mongodbadapter.NewAdapterByDB(client, &mongodbadapter.AdapterConfig{
    DatabaseName:   "my_app",
    CollectionName: "casbin_rule",
    OwnsClient:     true,
})
if err != nil {
    return err
}
// The adapter now owns client.
```

This intentionally changes the previous `NewAdapterByDB` behavior, which could
close an application-provided client during adapter cleanup. Constructors that
create their own client retain their existing cleanup behavior. Finalizers do
not guarantee prompt cleanup or execution before process exit.

## Filtered Policies

```go
import "github.com/globalsign/mgo/bson"

// This adapter also implements the FilteredAdapter interface. This allows for
// efficent, scalable enforcement of very large policies:
filter := &bson.M{"v0": "alice"}
e.LoadFilteredPolicy(filter)

// The loaded policy is now a subset of the policy in storage, containing only
// the policy lines that match the provided filter. This filter should be a
// valid MongoDB selector using BSON. A filtered policy cannot be saved.
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
