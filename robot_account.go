package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	harborRobotAccountType = "robot_account"
)

// harborToken defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *harborBackend) harborToken() *framework.Secret {
	return &framework.Secret{
		Type: harborRobotAccountType,
		Fields: map[string]*framework.FieldSchema{
			"robot_account": {
				Type:        framework.TypeString,
				Description: "Harbor Robot account",
			},
		},
		Revoke: b.robotAccountRevoke,
		Renew:  b.robotAccountRenew,
	}
}

// tokenRevoke removes the token from the Vault storage API and calls the client to revoke the robot account
func (b *harborBackend) robotAccountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("error getting Harbor client")
	}

	accountRaw, ok := req.Secret.InternalData["robot_account_name"]
	if !ok {
		return nil, fmt.Errorf("robot_account_name is missing on the lease")
	}

	// We passed the account using InternalData from when we first created
	// the secret. This is because the Harbor API uses the exact robot account name
	// for revocation.
	account, ok := accountRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable convert robot_account_name")
	}

	if err := deleteRobotAccount(ctx, client, account); err != nil {
		b.Logger().Warn(fmt.Sprintf("error revoking robot account: %s", err))
	}

	roleNameRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("role is missing on the lease")
	}

	roleName, ok := roleNameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable convert role")
	}

	err = req.Storage.Delete(ctx, b.getRobotPath(roleName))
	if err != nil {
		b.Logger().Warn(fmt.Sprintf("error delete in storage: %s", err))
	}
	return nil, nil
}

// deleteToken calls the Harbor client to delete the robot account
func deleteRobotAccount(ctx context.Context, c *harborClient, robotAccountName string) error {
	err := c.RESTClient.DeleteRobotAccountByName(ctx, robotAccountName)
	if err != nil {
		return err
	}

	return nil
}

// robotAccountRenew
func (b *harborBackend) robotAccountRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

func (b *harborBackend) setRobotToStorage(ctx context.Context, s logical.Storage, robot *harborRobotAccount) error {

	entry, err := logical.StorageEntryJSON(b.getRobotPath(robot.Role), robot)
	if err != nil {
		return err
	}

	// Write to storage to view user inventory
	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}
	return nil
}

func (b *harborBackend) getRobotFromStorage(ctx context.Context, s logical.Storage, robotAccountName string) (*harborRobotAccount, error) {
	if robotAccountName == "" {
		return nil, fmt.Errorf("missing username")
	}

	entry, err := s.Get(ctx, b.getRobotPath(robotAccountName))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var robot harborRobotAccount

	if err := entry.DecodeJSON(&robot); err != nil {
		return nil, err
	}
	return &robot, nil
}

func (b *harborBackend) getRobotPath(robotAccountName string) string {
	return fmt.Sprintf("robots/%s", robotAccountName)
}

/*
	for i, num := range b.Secrets {
		b.Logger().Info(fmt.Sprintf("found: %s, num: %d", num.Type, i))
	}
	creds2, err := req.Storage.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error creating Harbor robot account: %w", err)
	}
	for i, num := range creds2 {
		b.Logger().Info(fmt.Sprintf("found: %s, num: %d", num, i))
	}
*/
