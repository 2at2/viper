package remote

import (
	crypt "github.com/bketelsen/crypt/config"
	vault "github.com/spf13/viper/provider/vault"
	"io"
)

func NewStandardVaultConfigManager(machines []string) (crypt.ConfigManager, error) {
	store, err := vault.New(machines)
	if err != nil {
		return nil, err
	}
	return crypt.NewStandardConfigManager(store)
}

func NewVaultConfigManager(machines []string, keystore io.Reader) (crypt.ConfigManager, error) {
	store, err := vault.New(machines)
	if err != nil {
		return nil, err
	}
	return crypt.NewConfigManager(store, keystore)
}
