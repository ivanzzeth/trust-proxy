package doctor

import (
	"github.com/sagernet/nftables"
)

// probeNftablesNetlink performs the same probe sing-tun performs before it
// decides auto_redirect can work: open an nftables netlink socket and list the
// IPv4 tables. See sing-tun's redirect_linux.go initializeNFTables(), which is
// nftables.New() + ListTablesOfFamily(TableFamilyIPv4) and nothing else.
//
// It is deliberately identical rather than merely similar. A probe that answers
// a *different* question than the code it predicts is worse than no probe: it
// is a confident wrong answer. The previous implementation asked two other
// questions — is there an nft binary in PATH, and does /proc/net/netfilter/
// nf_tables stat — and CI caught both being wrong in the same container where
// auto_redirect demonstrably captured forwarded traffic.
func probeNftablesNetlink() (bool, string) {
	nft, err := nftables.New()
	if err != nil {
		return false, "nftables netlink socket: " + err.Error()
	}
	defer nft.CloseLasting()
	if _, err = nft.ListTablesOfFamily(nftables.TableFamilyIPv4); err != nil {
		return false, "nftables list tables: " + err.Error()
	}
	return true, ""
}
