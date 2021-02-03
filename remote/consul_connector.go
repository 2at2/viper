package remote

import (
	crypt "github.com/bketelsen/crypt/config"
	"github.com/spf13/viper/provider/consul"
	"io"
)

func NewStandardConsulConfigManager(machines []string) (crypt.ConfigManager, error) {
	store, err := consul.New(machines)
	if err != nil {
		return nil, err
	}
	return crypt.NewStandardConfigManager(store)
}

func NewConsulConfigManager(machines []string, keystore io.Reader) (crypt.ConfigManager, error) {
	store, err := consul.New(machines)
	if err != nil {
		return nil, err
	}
	return crypt.NewConfigManager(store, keystore)
}
