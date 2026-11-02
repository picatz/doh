#!/bin/sh
# doh-openwrt.sh: points an OpenWrt router's network at doh, at
#   192.168.1.10, fd00::10, 192.168.1.11
#
# Made by doh from profile default's setup. Over plain DNS, doh tells
# devices apart by address, so each device gets the profile whose devices
# or clients list its address (or the default profile). Give devices that
# need their own profile a fixed address: a static lease, in LuCI under
# Network, then DHCP and DNS, then Static Leases.
#
# Copy it to the router and run it there:
#   scp -O doh-openwrt.sh root@192.168.1.1:/tmp/
#   ssh root@192.168.1.1 sh /tmp/doh-openwrt.sh          (apply)
#   ssh root@192.168.1.1 sh /tmp/doh-openwrt.sh revert   (undo)
# using your router's address. It changes only /etc/config/dhcp, with uci,
# then restarts dnsmasq; devices pick up the new DNS server when they renew
# their lease, or reconnect.
#
# If doh itself forwards lookups to this router (doh serve --upstream with
# the router's address), leave out the dnsmasq lines, or lookups loop
# between the two. doh's own --forward of local names, such as lan, is
# fine: dnsmasq answers those itself.
set -eu

case "${1:-apply}" in
apply)
	# DHCP option 6 hands devices doh's IPv4 address as their DNS server, so
	# they ask doh directly, and doh sees each device's own address. The
	# del_list first keeps running this twice from adding it twice.
	uci -q del_list dhcp.lan.dhcp_option='6,192.168.1.10,192.168.1.11' || true
	uci add_list dhcp.lan.dhcp_option='6,192.168.1.10,192.168.1.11'
	# odhcpd announces doh's IPv6 addresses as DNS servers to IPv6 devices.
	uci -q del_list dhcp.lan.dns='fd00::10' || true
	uci add_list dhcp.lan.dns='fd00::10'
	# The router's own resolver, dnsmasq, forwards to doh too, so devices
	# that still ask the router (such as over IPv6, or with a cached lease),
	# and the router itself, go through doh. doh sees those as coming from
	# the router's address.
	uci -q del_list dhcp.@dnsmasq[0].server='192.168.1.10' || true
	uci add_list dhcp.@dnsmasq[0].server='192.168.1.10'
	uci -q del_list dhcp.@dnsmasq[0].server='fd00::10' || true
	uci add_list dhcp.@dnsmasq[0].server='fd00::10'
	uci -q del_list dhcp.@dnsmasq[0].server='192.168.1.11' || true
	uci add_list dhcp.@dnsmasq[0].server='192.168.1.11'
	# Use only doh, not also the DNS servers the internet provider hands the
	# router, which would let lookups skip doh.
	uci set dhcp.@dnsmasq[0].noresolv='1'
	;;
revert)
	# Take away what apply added.
	uci -q del_list dhcp.lan.dhcp_option='6,192.168.1.10,192.168.1.11' || true
	uci -q del_list dhcp.lan.dns='fd00::10' || true
	uci -q del_list dhcp.@dnsmasq[0].server='192.168.1.10' || true
	uci -q del_list dhcp.@dnsmasq[0].server='fd00::10' || true
	uci -q del_list dhcp.@dnsmasq[0].server='192.168.1.11' || true
	# Go back to the internet provider's DNS servers (OpenWrt's default).
	uci -q delete dhcp.@dnsmasq[0].noresolv || true
	;;
*)
	echo "usage: sh $0 [apply|revert]" >&2
	exit 2
	;;
esac

# Save the changes, and restart dnsmasq to use them.
uci commit dhcp
/etc/init.d/dnsmasq restart
