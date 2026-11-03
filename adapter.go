// Copyright 2018 The casbin Authors. All Rights Reserved.
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
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
)

const defaultTimeout time.Duration = 30 * time.Second
const defaultDatabaseName string = "casbin"
const defaultCollectionName string = "casbin_rule"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// adapter represents the MongoDB adapter for policy storage.
type adapter struct {
	client     *mongo.Client
	ownsClient bool
	collection *mongo.Collection
	timeout    time.Duration
	filtered   bool
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

// NewAdapter is the constructor for Adapter. If database name is not provided
// in the Mongo URL, 'casbin' will be used as database name.
// 'casbin_rule' will be used as a collection name.
func NewAdapter(url string, timeout ...interface{}) (persist.BatchAdapter, error) {
	if !strings.HasPrefix(url, "mongodb+srv://") && !strings.HasPrefix(url, "mongodb://") {
		url = fmt.Sprint("mongodb://" + url)
	}

	// Parse and validate url before apply it.
	connString, err := connstring.ParseAndValidate(url)

	if err != nil {
		return nil, err
	}

	clientOption := options.Client().ApplyURI(url)

	var databaseName string
	// Get database name from connString.
	if connString.Database != "" {
		databaseName = connString.Database
	} else {
		databaseName = defaultDatabaseName
	}

	return baseNewAdapter(clientOption, databaseName, defaultCollectionName, timeout...)
}

// NewAdapterWithClientOption is an alternative constructor for Adapter
// that does the same as NewAdapter, but uses mongo.ClientOption instead of a Mongo URL + a databaseName option
func NewAdapterWithClientOption(clientOption *options.ClientOptions, databaseName string, timeout ...interface{}) (persist.BatchAdapter, error) {
	return baseNewAdapter(clientOption, databaseName, defaultCollectionName, timeout...)
}

// NewAdapterWithCollectionName is an alternative constructor for Adapter
// that does the same as NewAdapterWithClientOption, but with an extra collectionName option
func NewAdapterWithCollectionName(clientOption *options.ClientOptions, databaseName string, collectionName string, timeout ...interface{}) (persist.BatchAdapter, error) {
	return baseNewAdapter(clientOption, databaseName, collectionName, timeout...)
}

// baseNewAdapter is a base constructor for Adapter
func baseNewAdapter(clientOption *options.ClientOptions, databaseName string, collectionName string, timeout ...interface{}) (persist.BatchAdapter, error) {
	a := &adapter{}
	a.filtered = false

	if len(timeout) == 1 {
		a.timeout = timeout[0].(time.Duration)
	} else if len(timeout) > 1 {
		return nil, errors.New("too many arguments")
	} else {
		a.timeout = defaultTimeout
	}

	// Open the DB, create it if not existed.
	err := a.open(clientOption, databaseName, collectionName)
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(url string) (persist.FilteredAdapter, error) {
	a, err := NewAdapter(url)
	if err != nil {
		return nil, err
	}
	a.(*adapter).filtered = true

	return a.(*adapter), nil
}

type AdapterConfig struct {
	DatabaseName   string
	CollectionName string
	Timeout        time.Duration
	IsFiltered     bool
	// OwnsClient makes the adapter responsible for disconnecting the client.
	// The default is false: the caller retains ownership of the client.
	OwnsClient bool
}

// NewAdapterByDB creates an adapter using an existing client.
// A nil config or a false OwnsClient leaves client cleanup to the caller.
func NewAdapterByDB(client *mongo.Client, config *AdapterConfig) (persist.BatchAdapter, error) {
	if config == nil {
		config = &AdapterConfig{}
	}
	if config.CollectionName == "" {
		config.CollectionName = defaultCollectionName
	}
	if config.DatabaseName == "" {
		config.DatabaseName = defaultDatabaseName
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}

	collection := client.Database(config.DatabaseName).Collection(config.CollectionName)

	a := &adapter{
		client:     client,
		ownsClient: config.OwnsClient,
		collection: collection,
		timeout:    config.Timeout,
		filtered:   config.IsFiltered,
	}

	if err := a.prepareIndexes(); err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func (a *adapter) open(clientOption *options.ClientOptions, databaseName string, collectionName string) error {
	client, err := mongo.Connect(clientOption)
	if err != nil {
		return err
	}

	db := client.Database(databaseName)
	collection := db.Collection(collectionName)

	a.client = client
	a.ownsClient = true
	a.collection = collection

	if err = a.prepareIndexes(); err != nil {
		return err
	}

	return nil
}

func (a *adapter) prepareIndexes() error {
	indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	keysDoc := bson.D{}

	for _, k := range indexes {
		keyDoc := bson.E{}
		keyDoc.Key = k
		keyDoc.Value = 1
		keysDoc = append(keysDoc, keyDoc)
	}

	if _, err := a.collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    keysDoc,
			Options: options.Index().SetUnique(true),
		},
	); err != nil {
		return err
	}

	return nil
}

func (a *adapter) close() {
	if !a.ownsClient {
		return
	}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	_ = a.client.Disconnect(ctx)
}

func loadPolicyLine(line CasbinRule, model model.Model) error {
	var p = []string{line.PType,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}

	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]
	err := persist.LoadPolicyArray(p, model)
	if err != nil {
		return err
	}
	return nil
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	return a.LoadFilteredPolicy(model, nil)
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		a.filtered = false
		filter = bson.D{{}}
	} else {
		a.filtered = true
	}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	cursor, err := a.collection.Find(ctx, filter)
	if err != nil {
		return err
	}

	for cursor.Next(ctx) {
		line := CasbinRule{}
		err := cursor.Decode(&line)
		if err != nil {
			return err
		}
		err = loadPolicyLine(line, model)
		if err != nil {
			return err
		}
	}

	return cursor.Close(ctx)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *adapter) IsFiltered() bool {
	return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
//
// The stored policy is replaced as a whole. The rules are collected from the
// model before the collection is touched, and the delete and the insert run
// inside a transaction when the server supports one, so that a failure can
// never leave the stored policy erased or half written.
func (a *adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}

	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	err := a.savePolicyTxn(lines)
	if err == nil {
		return nil
	}
	// (IllegalOperation) Transaction numbers are only allowed on a replica set member or mongos
	if mongoErr, ok := err.(mongo.CommandError); !ok || mongoErr.Code != 20 {
		return err
	}

	log.Println("[WARNING]: As your mongodb server doesn't allow a replica set, transaction operation is not supported. So Casbin Adapter will run non-transactional saving!")
	return a.savePolicy(lines)
}

// savePolicyTxn replaces the stored policy inside a transaction, so the old
// rules are only dropped if the new ones can be written in the same unit.
func (a *adapter) savePolicyTxn(lines []interface{}) error {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	session, err := a.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(context.TODO())

	_, err = session.WithTransaction(ctx, func(sessionCtx context.Context) (interface{}, error) {
		return nil, a.replacePolicy(sessionCtx, lines)
	})

	return err
}

// savePolicy replaces the stored policy without a transaction. It is the
// fallback for servers that are neither a replica set member nor a mongos.
func (a *adapter) savePolicy(lines []interface{}) error {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	return a.replacePolicy(ctx, lines)
}

// replacePolicy deletes every stored rule and writes the given ones in their
// place. The caller owns the context so that it can be run inside a session.
func (a *adapter) replacePolicy(ctx context.Context, lines []interface{}) error {
	res, err := a.collection.DeleteMany(ctx, bson.D{})
	if err != nil {
		return err
	}

	// Saving a model that holds no rules is a legitimate way to clear the
	// store, but InsertMany rejects an empty slice before it ever reaches the
	// server, so the delete above is all the work there is left to do.
	if len(lines) == 0 {
		if res.DeletedCount > 0 {
			log.Printf("[WARNING]: SavePolicy was called with an empty policy, %d stored rule(s) were deleted.", res.DeletedCount)
		}
		return nil
	}

	if _, err := a.collection.InsertMany(ctx, lines); err != nil {
		return err
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.InsertOne(ctx, line); err != nil {
		return err
	}

	return nil
}

// AddPolicies adds policy rules to the storage.
func (a *adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []interface{}
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()
	if _, err := a.collection.InsertMany(ctx, lines); err != nil {
		return err
	}
	return nil
}

// RemovePolicies removes policy rules from the storage.
func (a *adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}

	for _, line := range lines {
		ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
		defer cancel()
		if _, err := a.collection.DeleteOne(ctx, line); err != nil {
			return err
		}
	}

	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.DeleteOne(ctx, line); err != nil {
		return err
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.DeleteMany(ctx, selector); err != nil {
		return err
	}

	return nil
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := savePolicyLine(ptype, oldRule)
	newLine := savePolicyLine(ptype, newPolicy)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()
	// Updating all the documents equals to replacing
	_, err := a.collection.ReplaceOne(ctx, oldLine, newLine)
	return err
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	oldLines := make([]CasbinRule, 0, len(oldRules))
	newLines := make([]CasbinRule, 0, len(oldRules))
	for _, oldRule := range oldRules {
		oldLines = append(oldLines, savePolicyLine(ptype, oldRule))
	}
	for _, newRule := range newRules {
		newLines = append(newLines, savePolicyLine(ptype, newRule))
	}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()
	for i := range oldRules {
		_, err := a.collection.ReplaceOne(ctx, oldLines[i], newLines[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	oldLines := make([]CasbinRule, 0)
	newLines := make([]CasbinRule, 0, len(newPolicies))
	for _, newPolicy := range newPolicies {
		newLines = append(newLines, savePolicyLine(ptype, newPolicy))
	}

	oldPolicies, err := a.updateFilteredPoliciesTxn(oldLines, newLines, selector)
	if err == nil {
		return oldPolicies, err
	}
	// (IllegalOperation) Transaction numbers are only allowed on a replica set member or mongos
	if mongoErr, ok := err.(mongo.CommandError); !ok || mongoErr.Code != 20 {
		return nil, err
	}

	log.Println("[WARNING]: As your mongodb server doesn't allow a replica set, transaction operation is not supported. So Casbin Adapter will run non-transactional updating!")
	return a.updateFilteredPolicies(oldLines, newLines, selector)
}

func (a *adapter) updateFilteredPoliciesTxn(oldLines, newLines []CasbinRule, selector map[string]interface{}) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	session, err := a.client.StartSession()
	if err != nil {
		return nil, err
	}
	defer session.EndSession(context.TODO())

	_, err = session.WithTransaction(ctx, func(sessionCtx context.Context) (interface{}, error) {
		// Load old policies
		cursor, err := a.collection.Find(ctx, selector)
		if err != nil {
			_ = session.AbortTransaction(context.Background())
			return nil, err
		}
		for cursor.Next(ctx) {
			line := CasbinRule{}
			err := cursor.Decode(&line)
			if err != nil {
				_ = session.AbortTransaction(context.Background())
				return nil, err
			}
			oldLines = append(oldLines, line)
		}
		if err = cursor.Close(ctx); err != nil {
			_ = session.AbortTransaction(context.Background())
			return nil, err
		}

		// Delete all old policies
		if _, err := a.collection.DeleteMany(sessionCtx, selector); err != nil {
			_ = session.AbortTransaction(context.Background())
			return nil, err
		}
		// Insert new policies
		for _, newLine := range newLines {
			if _, err := a.collection.InsertOne(sessionCtx, &newLine); err != nil {
				_ = session.AbortTransaction(context.Background())
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldLines {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, nil
}

func (a *adapter) updateFilteredPolicies(oldLines, newLines []CasbinRule, selector map[string]interface{}) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	// Load old policies
	cursor, err := a.collection.Find(ctx, selector)
	if err != nil {
		return nil, err
	}
	for cursor.Next(ctx) {
		line := CasbinRule{}
		err := cursor.Decode(&line)
		if err != nil {
			return nil, err
		}
		oldLines = append(oldLines, line)
	}
	if err = cursor.Close(ctx); err != nil {
		return nil, err
	}

	// Delete all old policies
	if _, err := a.collection.DeleteMany(ctx, selector); err != nil {
		return nil, err
	}
	// Insert new policies
	for _, newLine := range newLines {
		if _, err := a.collection.InsertOne(ctx, &newLine); err != nil {
			return nil, err
		}
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldLines {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, nil
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.PType != "" {
		policy = append(policy, c.PType)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}
