package registry

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	username = "vault-plugin-testing"
	password = "Testing!123"
	url      = "http://localhost:1234"
)

// TestConfig mocks the creation, read, update, and delete
// of the backend configuration for HashiCups.
func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(b, reqStorage, map[string]interface{}{
			"username": username,
			"password": password,
			"url":      url,
		})
		assert.NoError(t, err)

		err = testConfigCreate(b, reqStorage, map[string]interface{}{
			"password": password,
			"url":      url,
		})
		assert.Error(t, err)

		err = testConfigCreate(b, reqStorage, map[string]interface{}{
			"username": username,
			"url":      url,
		})
		assert.Error(t, err)

		err = testConfigCreate(b, reqStorage, map[string]interface{}{
			"username": username,
			"password": password,
		})
		assert.Error(t, err)

		err = testConfigRead(b, reqStorage, map[string]interface{}{
			"username": username,
			"url":      url,
		})
		assert.NoError(t, err)

		err = testConfigUpdate(b, reqStorage, map[string]interface{}{
			"username": username,
			"url":      "http://harbor:1234",
		})
		assert.NoError(t, err)

		err = testConfigRead(b, reqStorage, map[string]interface{}{
			"username": username,
			"url":      "http://harbor:1234",
		})
		assert.NoError(t, err)

		err = testConfigDelete(b, reqStorage)
		assert.NoError(t, err)
	})
}

func testConfigDelete(b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigCreate(b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigUpdate(b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigRead(b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]

		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}
