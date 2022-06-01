package main

import (
	"flag"
	"github.com/go-ini/ini"
)

var serverConfig struct {
	cookieDomain  string
	authSubdomain string
	listenAddress string
	insecure      bool
}

func updateConfig(args []string) error {
	fset := flag.NewFlagSet("", flag.ContinueOnError)
	fset.StringVar(&serverConfig.cookieDomain, "cookieDomain", "", "The domain that the cookie is limited to")
	fset.StringVar(&serverConfig.authSubdomain, "authSubdomain", "", "convAuth's subdomain relative to --cookieDomain")
	fset.StringVar(&serverConfig.listenAddress, "listenAddress", ":8080", "Address the server listens on")
	fset.BoolVar(&serverConfig.insecure, "insecure", false, "Turn off cookie security feaatures, and HSTS")

	_ = ini.MapTo(&serverConfig, authProxyConfig)

	return fset.Parse(args)
}
