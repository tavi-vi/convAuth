package main

import (
	"flag"
	"github.com/go-ini/ini"
	"log"
	"reflect"
)

var serverConfig struct {
	CookieDomain  string
	ListenAddress string
	Insecure      bool
}

func updateConfig(args []string) error {
	fset := flag.NewFlagSet("", flag.ContinueOnError)
	fset.StringVar(&serverConfig.CookieDomain, "CookieDomain", "", "The domain that the cookie is limited to")
	fset.StringVar(&serverConfig.ListenAddress, "ListenAddress", ":8080", "Address the server listens on")
	fset.BoolVar(&serverConfig.Insecure, "Insecure", false, "Turn off cookie security features, and HSTS")

	// Doesn't this feel a little silly? I might as well write my own INI parser.
	if f, err := ini.Load(authProxyConfig); err == nil {
		scT := reflect.TypeOf(serverConfig)
		validFields := make(map[string]struct{})
		for _, k := range reflect.VisibleFields(scT) {
			validFields[k.Name] = struct{}{}
		}
		ds, _ := f.GetSection(ini.DEFAULT_SECTION)
		if err != nil {
			panic(err)
		}
		for k, _ := range ds.KeysHash() {
			_, ok := validFields[k]
			if !ok {
				log.Printf("Invalid key '%s' in config file %s", k, authProxyConfig)
			}
		}

		_ = f.MapTo(&serverConfig)
	}

	return fset.Parse(args)
}
