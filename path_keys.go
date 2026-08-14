// SPDX-License-Identifier: MPL-2.0

package secp256k1signer

import (
	"context"
	"strconv"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const keyNamePattern = "(?P<name>[a-zA-Z0-9_-]+)"

func (b *backend) pathKeysList() *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleKeysList},
		},
		HelpSynopsis: "List the names of the keys held by this mount.",
	}
}

func (b *backend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + keyNamePattern + "$",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "Name of the key."},
		},
		ExistenceCheck: b.keyExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleKeyCreate},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleKeyCreateExisting},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleKeyRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleKeyDelete},
		},
		HelpSynopsis: "Create, read, or delete a secp256k1 key. Key material is non-exportable: reads return public material only.",
	}
}

func (b *backend) pathKeysConfig() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + keyNamePattern + "/config$",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "Name of the key."},
			"deletion_allowed": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Whether the key may be deleted. Defaults to false.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleKeyConfig},
		},
		HelpSynopsis: "Configure key settings. Only deletion_allowed is configurable; there is no exportable setting to misconfigure.",
	}
}

func (b *backend) pathKeysRotate() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + keyNamePattern + "/rotate$",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString, Description: "Name of the key."},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleKeyRotate},
		},
		HelpSynopsis: "Rotate the key to a new version. Earlier versions remain stored and may still be requested for signing explicitly.",
	}
}

func (b *backend) keyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	// Existence needs no decoded private material (SEC-002): fetch the raw
	// entry, wipe the buffer, answer from presence alone.
	raw, err := req.Storage.Get(ctx, keyStoragePrefix+d.Get("name").(string))
	if err != nil {
		return false, err
	}
	if raw == nil {
		return false, nil
	}
	wipeBytes(raw.Value)
	return true, nil
}

func (b *backend) handleKeysList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, keyStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) handleKeyCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.keyLock.Lock()
	defer b.keyLock.Unlock()

	existing, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		existing.wipe()
		return logical.ErrorResponse("key %q already exists; use keys/%s/rotate to rotate it", name, name), nil
	}

	kv, err := newKeyVersion()
	if err != nil {
		return nil, err
	}
	entry := &keyEntry{
		Versions:      map[int]*keyVersion{1: kv},
		LatestVersion: 1,
	}
	defer entry.wipe()
	if err := b.putKey(ctx, req.Storage, name, entry); err != nil {
		return nil, err
	}
	return b.keyReadResponse(name, entry)
}

func (b *backend) handleKeyCreateExisting(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	return logical.ErrorResponse("key %q already exists; use keys/%s/rotate to rotate it", name, name), nil
}

func (b *backend) handleKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	defer entry.wipe()
	return b.keyReadResponse(name, entry)
}

func (b *backend) keyReadResponse(name string, entry *keyEntry) (*logical.Response, error) {
	versions := make(map[string]any, len(entry.Versions))
	for v, kv := range entry.Versions {
		data, err := kv.publicData()
		if err != nil {
			return nil, err
		}
		versions[strconv.Itoa(v)] = data
	}
	return &logical.Response{
		Data: map[string]any{
			"name":             name,
			"type":             "secp256k1",
			"latest_version":   entry.LatestVersion,
			"deletion_allowed": entry.DeletionAllowed,
			"versions":         versions,
		},
	}, nil
}

func (b *backend) handleKeyConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.keyLock.Lock()
	defer b.keyLock.Unlock()

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("key %q not found", name), nil
	}
	defer entry.wipe()
	entry.DeletionAllowed = d.Get("deletion_allowed").(bool)
	if err := b.putKey(ctx, req.Storage, name, entry); err != nil {
		return nil, err
	}
	return b.keyReadResponse(name, entry)
}

func (b *backend) handleKeyRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.keyLock.Lock()
	defer b.keyLock.Unlock()

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("key %q not found", name), nil
	}
	defer entry.wipe()
	kv, err := newKeyVersion()
	if err != nil {
		return nil, err
	}
	entry.LatestVersion++
	entry.Versions[entry.LatestVersion] = kv
	if err := b.putKey(ctx, req.Storage, name, entry); err != nil {
		return nil, err
	}
	return b.keyReadResponse(name, entry)
}

func (b *backend) handleKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.keyLock.Lock()
	defer b.keyLock.Unlock()

	entry, err := b.getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	defer entry.wipe()
	if !entry.DeletionAllowed {
		return logical.ErrorResponse("deletion of key %q is not allowed; set deletion_allowed via keys/%s/config first", name, name), nil
	}
	if err := req.Storage.Delete(ctx, keyStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}
