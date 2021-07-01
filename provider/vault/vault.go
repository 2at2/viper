package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"log"
	"os"
	"time"

	"github.com/bketelsen/crypt/backend"

	vaultapi "github.com/hashicorp/vault/api"
)

var logger = logrus.New()

type Client struct {
	client *vaultapi.Client
}

func New(machines []string) (*Client, error) {
	vaultRoleId := os.Getenv("VAULT_ROLE_ID")
	vaultSecretId := os.Getenv("VAULT_SECRET_ID")
	vaultToken := os.Getenv("VAULT_TOKEN")

	conf := vaultapi.DefaultConfig()

	if len(machines) > 0 {
		conf.Address = machines[0]
	}

	client, err := vaultapi.NewClient(conf)
	if err != nil {
		return nil, err
	}

	if len(vaultRoleId) > 0 {
		logger.Debugf("App role authentication")

		if err := loginAppRole(client, vaultRoleId, vaultSecretId); err != nil {
			return nil, err
		}

		secret, err := client.Auth().Token().LookupSelf()
		if err != nil {
			return nil, err
		}

		var token struct {
			Renewable bool
			TTL       int
		}
		if err := mapstructure.Decode(secret.Data, &token); err != nil {
			return nil, err
		}

		lifetimeWatcher, err := client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
			Secret: &vaultapi.Secret{
				Auth: &vaultapi.SecretAuth{
					ClientToken:   client.Token(),
					Renewable:     token.Renewable,
					LeaseDuration: secret.LeaseDuration,
				},
			},
			Increment:     token.TTL,
			RenewBehavior: vaultapi.RenewBehaviorIgnoreErrors,
		})
		if err != nil {
			return nil, err
		}

		go renewToken(context.Background(), lifetimeWatcher)
	} else if len(vaultToken) > 0 {
		logger.Debugf("Token auth mode")
		client.SetToken(vaultToken)
	} else {
		return nil, fmt.Errorf("unknown auth method")
	}

	return &Client{client}, nil
}

func (c *Client) Get(key string) ([]byte, error) {
	data, err := c.client.Logical().Read(key)
	if err != nil {
		log.Printf("Error during Vault Get - %s", err)
		return []byte{}, err
	}

	if data == nil {
		return nil, fmt.Errorf("source not found: %s", key)
	}
	if data.Data == nil {
		return []byte{}, fmt.Errorf("key %s was not found", key)
	}

	bts, err := json.Marshal(data.Data)
	if err != nil {
		log.Printf("Unable to marshal vault secret data - %s", err)
		return nil, err
	}

	return bts, nil
}

func (c *Client) List(key string) (backend.KVPairs, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Client) Set(key string, value []byte) error {
	secretData := map[string]interface{}{
		"value": value,
	}
	_, err := c.client.Logical().Write(key, secretData)

	return err
}

func (c *Client) Watch(key string, stop chan bool) <-chan *backend.Response {
	respChan := make(chan *backend.Response, 0)
	go func() {
		for {
			data, err := c.client.Logical().Read(key)
			if data == nil && err == nil {
				err = fmt.Errorf("Key ( %s ) was not found.", key)
			}
			if err != nil {
				respChan <- &backend.Response{Value: nil, Error: err}
				time.Sleep(time.Second * 5)
				continue
			}

			bts, err := json.Marshal(data.Data)
			if err != nil {
				log.Printf("Unable to marshal vault secret data - %s", err)
				respChan <- &backend.Response{Value: nil, Error: err}
			} else {
				respChan <- &backend.Response{Value: bts}
			}
		}
	}()
	return respChan
}

func loginAppRole(client *vaultapi.Client, role string, secret string) error {
	data, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   role,
		"secret_id": secret,
	})
	if err != nil {
		return err
	}

	token, err := data.TokenID()
	if err != nil {
		return err
	}

	client.SetToken(token)

	return nil
}

func renewToken(ctx context.Context, watcher *vaultapi.LifetimeWatcher) {
	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case err := <-watcher.DoneCh():
			if err != nil {
				logger.Errorf("Error renewing token for Vault provider - %s", err)
			}

			// Watcher routine has finished, so start it again.
			go watcher.Start()

		case <-watcher.RenewCh():
			logger.Debug("Successfully renewed token for Vault provider")
		}
	}
}
