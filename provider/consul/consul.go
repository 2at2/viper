package consul

import (
	"encoding/json"
	"fmt"
	"github.com/bketelsen/crypt/backend"
	"github.com/hashicorp/consul/api"
	"log"
	"strings"
)

type Client struct {
	client *api.KV
	secret string
}

func New(machines []string) (*Client, error) {
	consulConfig := api.DefaultConfig()
	if len(machines) > 0 {
		consulConfig.Address = machines[0]
	} else {
		return nil, fmt.Errorf("no consul addr")
	}

	// Create a Consul API client
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: consulClient.KV(),
	}, nil
}

func (c *Client) Get(prefix string) ([]byte, error) {
	prefixLen := len(prefix)

	kvPairs, _, err := c.client.List(prefix, &api.QueryOptions{
		Token: c.secret,
	})

	if err != nil {
		log.Printf("Error during Vault Get - %s", err)
		return []byte{}, err
	}

	data := make(map[string]interface{})
	for _, kv := range kvPairs {
		name := strings.ReplaceAll(kv.Key[prefixLen+1:], "/", ".")

		var raw interface{}
		if err := json.Unmarshal(kv.Value, &raw); err == nil {
			data[name] = raw
		} else {
			data[name] = fmt.Sprintf("%s", kv.Value)
		}
	}

	bts, err := json.Marshal(data)
	if err != nil {
		log.Printf("Unable to marshal vault secret data - %s", err)
		return nil, err
	}

	return bts, nil
}

func (c *Client) List(key string) (backend.KVPairs, error) {
	// TODO: NOT IMPLEMENTED
	return nil, nil
}

func (c *Client) Set(key string, value []byte) error {
	return nil
}

func (c *Client) Watch(key string, stop chan bool) <-chan *backend.Response {
	respChan := make(chan *backend.Response, 0)
	// TODO: NOT IMPLEMENTED
	return respChan
}
