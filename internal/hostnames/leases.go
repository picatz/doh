package hostnames

import (
	"bufio"
	"context"
	"encoding/csv"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// leasesCheckInterval bounds how often a lease file is checked for changes.
const leasesCheckInterval = 5 * time.Second

// maxLeasesSize bounds the size of a lease file.
const maxLeasesSize = 16 << 20

// Leases looks names up in a DHCP server's lease file, for when doh runs
// beside the DHCP server, such as on a router or a Raspberry Pi that hands
// out addresses. It reads, and rereads when they change:
//
//   - dnsmasq's lease file (as on OpenWrt and Pi-hole), with lines of
//     "expiry mac address hostname client-id", where "*" means no name.
//   - Kea's memfile CSV lease files, with a header naming the "address"
//     and "hostname" columns.
//
// Expired leases are ignored.
type Leases struct {
	// Path is the lease file.
	Path string

	mu      sync.Mutex
	checked time.Time
	modTime time.Time
	names   map[netip.Addr]string
}

// Lookup implements [Source].
func (l *Leases) Lookup(_ context.Context, addr netip.Addr) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.refresh(); err != nil {
		return "", err
	}
	return l.names[addr.Unmap()], nil
}

// refresh rereads the file if it changed, at most every
// leasesCheckInterval. l.mu must be held.
func (l *Leases) refresh() error {
	now := time.Now()
	if l.names != nil && now.Sub(l.checked) < leasesCheckInterval {
		return nil
	}
	l.checked = now

	f, err := os.Open(l.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if l.names != nil && info.ModTime().Equal(l.modTime) {
		return nil
	}

	names, err := ParseLeases(io.LimitReader(f, maxLeasesSize), now)
	if err != nil {
		return err
	}
	l.names, l.modTime = names, info.ModTime()
	return nil
}

// ParseLeases reads a dnsmasq or Kea lease file, returning the hostname of
// each address with an unexpired lease at now.
func ParseLeases(r io.Reader, now time.Time) (map[netip.Addr]string, error) {
	br := bufio.NewReader(r)
	first, err := br.Peek(64)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if strings.HasPrefix(string(first), "address,") {
		return parseKea(br, now)
	}
	return parseDnsmasq(br, now)
}

// parseDnsmasq reads dnsmasq's lease file.
func parseDnsmasq(r io.Reader, now time.Time) (map[netip.Addr]string, error) {
	names := make(map[netip.Addr]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] == "*" {
			continue // DHCPv6 "duid" lines, and leases without names
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		if expiry, err := strconv.ParseInt(fields[0], 10, 64); err == nil && expiry != 0 && now.Unix() >= expiry {
			continue // 0 means a lease that never expires
		}
		names[addr.Unmap()] = fields[3]
	}
	return names, sc.Err()
}

// parseKea reads Kea's memfile CSV lease file.
func parseKea(r io.Reader, now time.Time) (map[netip.Addr]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, name := range header {
		col[name] = i
	}
	addrCol, okAddr := col["address"]
	nameCol, okName := col["hostname"]
	expireCol, okExpire := col["expire"]
	stateCol, okState := col["state"]
	if !okAddr || !okName {
		return map[netip.Addr]string{}, nil
	}

	names := make(map[netip.Addr]string)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return names, nil
		}
		if err != nil {
			continue // a malformed line, perhaps half written
		}
		if len(rec) <= max(addrCol, nameCol) || rec[nameCol] == "" {
			continue
		}
		addr, err := netip.ParseAddr(rec[addrCol])
		if err != nil {
			continue
		}
		// Kea appends a line per lease change, and the last one wins:
		// a lease declined or reclaimed (a state other than 0) has no
		// name any more.
		if okState && len(rec) > stateCol && rec[stateCol] != "0" {
			delete(names, addr.Unmap())
			continue
		}
		if okExpire && len(rec) > expireCol {
			if expiry, err := strconv.ParseInt(rec[expireCol], 10, 64); err == nil && now.Unix() >= expiry {
				continue
			}
		}
		names[addr.Unmap()] = rec[nameCol]
	}
}
