package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	//nolint:gosec
	pathCredsHelpSyn  = `Generate a Harbor robot account from a specific Vault role.`
	pathCredsHelpDesc = `This path generates a Harbor robot account
based on a particular role.`

	dayHours = float64(24)
)

// harborRobotAccount defines a secret for the Harbor token
type harborRobotAccount struct {
	ID        int64  `json:"robot_account_id"`
	Role      string `json:"robot_role_name"`
	Name      string `json:"robot_account_name"`
	Secret    string `json:"robot_account_secret"`
	AuthToken string `json:"robot_account_auth_token"`
}

func (robotAccount *harborRobotAccount) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"robot_account_id":         robotAccount.ID,
		"robot_role_name":          robotAccount.Role,
		"robot_account_name":       robotAccount.Name,
		"robot_account_secret":     robotAccount.Secret,
		"robot_account_auth_token": robotAccount.AuthToken,
	}
	return respData
}

// pathCreds extends the Vault API with a `/creds`
// endpoint for a role.
func pathCreds(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredsRead,
			logical.UpdateOperation: b.pathCredsRead,
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

// pathCredentialsRead creates a new Harbor robot account each time it is called if a
// role exists.
func (b *harborBackend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createCreds(ctx, req, roleName, roleEntry)
}

// createCreds creates a new Harbor robot account to store into the Vault backend, generates
// a response with the robot account information, and checks the TTL and MaxTTL attributes.
func (b *harborBackend) createCreds(
	ctx context.Context,
	req *logical.Request,
	roleName string,
	role *harborRoleEntry,
) (*logical.Response, error) {
	var displayName string

	if req.DisplayName != "" {
		re := regexp.MustCompile("[^[:alnum:]._-]")
		dn := re.ReplaceAllString(req.DisplayName, "-")
		displayName = fmt.Sprintf("%s.", dn)
	}
	//logger := hclog.New(&hclog.LoggerOptions{})
	robotAccount, err := b.getRobotFromStorage(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if robotAccount == nil {
		robotAccountName := fmt.Sprintf("vault.%s.%s%d", roleName, displayName, time.Now().UnixNano())
		robotAccount, err = b.createRobotAccount(ctx, req.Storage, robotAccountName, roleName, role)
		if err != nil {
			return nil, err
		}
		err = b.setRobotToStorage(ctx, req.Storage, robotAccount)
		if err != nil {
			return nil, err
		}
	}

	internalData := map[string]interface{}{
		"role":               roleName,
		"robot_account_name": robotAccount.Name,
	}

	// The response is divided into two objects (1) internal data and (2) data.
	resp := b.Secret(harborRobotAccountType).Response(robotAccount.toResponseData(), internalData)

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

// createRobotAccount uses the Harbor client to create and return a robot account
func (b *harborBackend) createRobotAccount(
	ctx context.Context,
	s logical.Storage,
	robotName string,
	roleName string,
	roleEntry *harborRoleEntry,
) (*harborRobotAccount, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	maxTTLByDay := int64(roleEntry.MaxTTL.Hours()/dayHours) + 1

	robotCreate := &harborModel.RobotCreate{
		Name:        robotName,
		Description: "This robot account is created by Vault, please DO NOT edit!",
		Disable:     false,
		Duration:    maxTTLByDay,
		Level:       "system",
		Permissions: roleEntry.Permissions,
	}

	robotCreated, err := client.RESTClient.NewRobotAccount(ctx, robotCreate)
	if err != nil {
		return nil, fmt.Errorf("error creating Harbor robot account: %w", err)
	}

	robotToken := fmt.Sprintf("%s:%s", robotCreated.Name, robotCreated.Secret)

	robotAccount := &harborRobotAccount{
		ID:        robotCreated.ID,
		Role:      roleName,
		Name:      robotCreated.Name,
		Secret:    robotCreated.Secret,
		AuthToken: base64.StdEncoding.EncodeToString([]byte(robotToken)),
	}

	return robotAccount, nil
}
