// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	secp256k1signer "github.com/IndependentImpact/openbao-plugin-secp256k1"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: secp256k1signer.Factory,
		// TLSProviderFunc is only the fallback for servers without plugin
		// AutoMTLS; current OpenBao negotiates mTLS automatically.
		TLSProviderFunc: tlsProviderFunc,
	}); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
