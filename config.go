package main

import (
	"flag"
	"github.com/go-ini/ini"
)

var serverConfig struct {
	cookieDomain   string
	listenAddress  string
	insecureCookie bool
}

func updateConfig(args []string) error {
	fset := flag.NewFlagSet("", flag.ContinueOnError)
	fset.StringVar(&serverConfig.cookieDomain, "cookieDomain", "", "The domain that the cookie is limited to")
	fset.StringVar(&serverConfig.listenAddress, "listenAddress", ":8080", "Address the server listens on")
	fset.BoolVar(&serverConfig.insecureCookie, "insecureCookie", false, "Turn off cookie security features (for testing)")

	_ = ini.MapTo(&serverConfig, authProxyConfig)

	return fset.Parse(args)
}
