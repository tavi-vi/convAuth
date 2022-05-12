package main

import (
	"errors"
	"flag"
	"github.com/go-ini/ini"
	"os"
)

var serverConfig struct {
	cookieDomain  string
	listenAddress string
}

func readConfigFile(path string) error {
	cfg, err := ini.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	k := cfg.Section("").Key("listenAddress")
	if k != nil {
		serverConfig.listenAddress = k.String()
	}
	k = cfg.Section("").Key("cookieDomain")
	if k != nil {
		serverConfig.cookieDomain = k.String()
	}
	return nil
}

func updateConfig(args []string) error {
	fset := flag.NewFlagSet("", flag.ContinueOnError)
	fset.StringVar(&serverConfig.cookieDomain, "cookieDomain", "", "The domain that the cookie is limited to")
	fset.StringVar(&serverConfig.listenAddress, "listenAddress", ":8080", "Address the server listens on")

	err := readConfigFile(authProxyConfig)

	err = fset.Parse(args)
	if err != nil {
		return err
	}

	return nil
}
