package devicesetup

// windowsScript is the Windows setup script. Values in {{braces}} are
// replaced, after being checked to need no quoting.
const windowsScript = `<#
.SYNOPSIS
    Sends this PC's DNS to doh, encrypted with DNS over HTTPS, using
    {{selects}}.

.DESCRIPTION
    Made by doh for {{hostname}}. Read it before running it: it only
    changes this PC's DNS settings, and fetches nothing from the internet.

    What it does, step by step:

    1. Finds doh's addresses: the ones below (-ServerAddress), or, if
       there are none, what {{hostname}} resolves to right now.
    2. Tells Windows that those addresses speak DNS over HTTPS at
       {{template}},
       with no fallback to unencrypted DNS (Add-DnsClientDohServerAddress).
       The URL's path is how doh knows the profile and device.
    3. Sets the DNS servers of each connected network adapter (or the ones
       named with -InterfaceAlias) to those addresses
       (Set-DnsClientServerAddress), so Windows uses doh for every lookup.
    4. Clears the DNS cache, so new lookups go to doh straight away.

    -Revert undoes it: it forgets the DNS over HTTPS template, and sets
    the adapters back to the DNS servers the network hands out (DHCP). If
    you had typed in DNS servers of your own before, set them again.

    Windows 11 (and Windows Server 2022) have DNS over HTTPS built in.
    Windows 10 doesn't; there, use your browser's secure DNS setting
    instead, which this script can't do for you.

.PARAMETER ServerAddress
    doh's addresses. The default is what doh knew when it made this
    script; with none, the script looks up {{hostname}}.

.PARAMETER InterfaceAlias
    The network adapters to change, such as "Wi-Fi" or "Ethernet". The
    default is every adapter that's up and has a default gateway.

.PARAMETER Revert
    Undo the changes this script makes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\doh-setup.ps1 -WhatIf

    Shows what it would change, changing nothing. Bypass applies to this
    one run only; it doesn't change your execution policy.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\doh-setup.ps1

    Run from PowerShell opened as administrator, it makes the changes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\doh-setup.ps1 -Revert

    Undoes them.
#>

# SupportsShouldProcess gives the script -WhatIf and -Confirm: every change
# below asks $PSCmdlet.ShouldProcess first, which, with -WhatIf, only says
# what it would do.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]] $ServerAddress = {{addrs}},
    [string[]] $InterfaceAlias,
    [switch] $Revert
)

# Stop at the first error, rather than carry on half done.
$ErrorActionPreference = 'Stop'

# The DNS over HTTPS URL that selects {{selects}}.
$Template = '{{template}}'

# The server's host name, looked up if no addresses are known.
$HostName = '{{hostname}}'

# Windows 10 has no built-in DNS over HTTPS, so these commands are missing.
if (-not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
    throw 'This version of Windows has no built-in DNS over HTTPS (Windows 11 and Windows Server 2022 do). Use your browser''s secure DNS setting instead.'
}

# Changing DNS settings needs an administrator; -WhatIf doesn't.
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $WhatIfPreference -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from PowerShell opened as administrator (right-click it, then Run as administrator).'
}

# The adapters to change: the ones named, or every connected one with a
# default gateway, which is how it reaches the internet.
if (-not $InterfaceAlias) {
    $InterfaceAlias = @(Get-NetIPConfiguration |
        Where-Object { $_.NetAdapter.Status -eq 'Up' -and ($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway) } |
        ForEach-Object { $_.InterfaceAlias })
}
if (-not $InterfaceAlias) {
    throw 'No connected network adapter was found. Name one with -InterfaceAlias, such as -InterfaceAlias Wi-Fi.'
}

if ($Revert) {
    # Forget every address registered with this script's template.
    foreach ($server in @(Get-DnsClientDohServerAddress | Where-Object { $_.DohTemplate -eq $Template })) {
        if ($PSCmdlet.ShouldProcess($server.ServerAddress, 'Remove the DNS over HTTPS template')) {
            Remove-DnsClientDohServerAddress -ServerAddress $server.ServerAddress
        }
    }
    # Go back to the DNS servers the network hands out.
    foreach ($alias in $InterfaceAlias) {
        if ($PSCmdlet.ShouldProcess($alias, 'Use the DNS servers the network hands out (DHCP)')) {
            Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses
        }
    }
} else {
    # Look up doh's addresses if none are given. This uses the PC's DNS as
    # it is now, before anything changes.
    if (-not $ServerAddress) {
        $ServerAddress = @(Resolve-DnsName -Name $HostName -Type A_AAAA -DnsOnly |
            Where-Object { $_.IPAddress } |
            ForEach-Object { $_.IPAddress })
    }
    if (-not $ServerAddress) {
        throw "Couldn't find $HostName's address. Give it with -ServerAddress."
    }

    # Register the template for each address: AutoUpgrade has Windows use
    # DNS over HTTPS whenever it asks that address, and AllowFallbackToUdp
    # off means it never falls back to unencrypted DNS. Set replaces an
    # existing registration; Add makes a new one.
    foreach ($address in $ServerAddress) {
        if ($PSCmdlet.ShouldProcess($address, "Use DNS over HTTPS at $Template, with no unencrypted fallback")) {
            if (Get-DnsClientDohServerAddress -ServerAddress $address -ErrorAction SilentlyContinue) {
                Set-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true
            } else {
                Add-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true
            }
        }
    }

    # Point each adapter at doh, and only doh: a second, public DNS server
    # would let lookups skip it.
    foreach ($alias in $InterfaceAlias) {
        if ($PSCmdlet.ShouldProcess($alias, "Set the DNS servers to $($ServerAddress -join ', ')")) {
            Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $ServerAddress
        }
    }
}

# Forget cached answers, so the next lookups use the new settings.
if ($PSCmdlet.ShouldProcess('the DNS client cache', 'Clear')) {
    Clear-DnsClientCache
}

# Show where things stand.
if (-not $WhatIfPreference) {
    Get-DnsClientDohServerAddress | Where-Object { $_.DohTemplate -eq $Template } | Format-Table -AutoSize
    Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias | Format-Table -AutoSize
}
`

// resolvedDropIn is the systemd-resolved drop-in.
const resolvedDropIn = `# {{path}}
#
# Sends this computer's DNS to doh, encrypted with DNS-over-TLS, using
# {{selects}}.
#
# Install it:
#   sudo mkdir -p /etc/systemd/resolved.conf.d
#   sudo cp {{file}} {{path}}
#   sudo systemctl restart systemd-resolved
# Check it:
#   resolvectl status        (Global shows +DNSOverTLS and the servers below)
#   resolvectl query example.com
# Undo it:
#   sudo rm {{path}}
#   sudo systemctl restart systemd-resolved
#
# It works where /etc/resolv.conf points at systemd-resolved (nameserver
# 127.0.0.53), as on Ubuntu, Fedora, and Debian with systemd-resolved.

[Resolve]
# doh's addresses, each with the TLS server name that tells doh the
# profile and device, on the standard DNS-over-TLS port, 853.
DNS={{servers}}
# Encrypt every query, and never fall back to unencrypted DNS: if doh
# can't be reached, lookups fail rather than leak.
DNSOverTLS=yes
# Use these servers for every domain, rather than the DNS servers each
# network hands out (which NetworkManager passes on to systemd-resolved).
Domains=~.
`

// openWrtScript is the OpenWrt setup script.
const openWrtScript = `#!/bin/sh
# {{file}}: points an OpenWrt router's network at doh, at
#   {{addrs}}
#
# Made by doh from profile {{profile}}'s setup. Over plain DNS, doh tells
# devices apart by address, so each device gets the profile whose devices
# or clients list its address (or the default profile). Give devices that
# need their own profile a fixed address: a static lease, in LuCI under
# Network, then DHCP and DNS, then Static Leases.
#
# Copy it to the router and run it there:
#   scp -O {{file}} root@192.168.1.1:/tmp/
#   ssh root@192.168.1.1 sh /tmp/{{file}}          (apply)
#   ssh root@192.168.1.1 sh /tmp/{{file}} revert   (undo)
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
{{apply}}	;;
revert)
	# Take away what apply added.
{{revert}}	;;
*)
	echo "usage: sh $0 [apply|revert]" >&2
	exit 2
	;;
esac

# Save the changes, and restart dnsmasq to use them.
uci commit dhcp
/etc/init.d/dnsmasq restart
`
