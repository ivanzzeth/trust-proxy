package gateway

import (
	"runtime"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// tunAutoRedirectEnabled reports whether the merged tun inbound should carry
// auto_redirect. sing-box only accepts the field on Linux (nftables); elsewhere
// we omit it even if the store says true, so a macOS desktop sharing the same
// tun.json shape does not fail to start.
func tunAutoRedirectEnabled(tun apitypes.TUNConfig) bool {
	return tun.AutoRedirect && runtime.GOOS == "linux"
}
