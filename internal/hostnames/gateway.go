package hostnames

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strings"
)

// DefaultGateway returns the IPv4 address of the system's default gateway,
// usually the router, which on most home networks also answers DNS
// queries for its DHCP clients' names. It reads Linux's routing table, so
// elsewhere it reports false.
func DefaultGateway() (netip.Addr, bool) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	defer f.Close()
	return parseRoutes(f)
}

// parseRoutes finds the default route's gateway in a Linux
// /proc/net/route table, whose addresses are little-endian hex.
func parseRoutes(r io.Reader) (netip.Addr, bool) {
	sc := bufio.NewScanner(r)
	sc.Scan() // the header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
		if gw := netip.AddrFrom4(a); !gw.IsUnspecified() {
			return gw, true
		}
	}
	return netip.Addr{}, false
}
