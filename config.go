package main

import (
	"flag"
	"github.com/go-ini/ini"
)

var serverConfig struct {
	cookieDomain  string
	listenAddress string
}

func updateConfig(args []string) error {
	fset := flag.NewFlagSet("", flag.ContinueOnError)
	fset.StringVar(&serverConfig.cookieDomain, "cookieDomain", "", "The domain that the cookie is limited to")
	fset.StringVar(&serverConfig.listenAddress, "listenAddress", ":8080", "Address the server listens on")

	cfg, err := ini.Load(authProxyConfig)
	if err == nil {
		k := cfg.Section("").Key("listenAddress")
		if k != nil {
			serverConfig.listenAddress = k.String()
		}
		k = cfg.Section("").Key("cookieDomain")
		if k != nil {
			serverConfig.cookieDomain = k.String()
		}
	}

	return fset.Parse(args)
}
