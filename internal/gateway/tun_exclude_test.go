package gateway

import (
	"runtime"
	"testing"
)

func TestTunPrivateRouteExcludesDesktopOnly(t *testing.T) {
	got := tunPrivateRouteExcludes()
	if runtime.GOOS == "linux" {
		if got != nil {
			t.Fatalf("linux excludes = %v, want nil (Docker/CNI must stay capturable)", got)
		}
		return
	}
	if len(got) != len(PrivateCIDRs()) {
		t.Fatalf("desktop excludes = %v, want PrivateCIDRs %v", got, PrivateCIDRs())
	}
	for i, p := range PrivateCIDRs() {
		if got[i] != p {
			t.Fatalf("excludes[%d]=%s want %s", i, got[i], p)
		}
	}
}
