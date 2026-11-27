#!/bin/sh
# tool-inventory.sh — write the build-time tool inventory that list_tools reads
# (agent/listtools.go, docs/offline-toolbox.md §6.1) as JSON on stdout.
#
# Usage (Dockerfile, runtime stage):
#   tool-inventory.sh PINNED_TSV BASE_VERSION [name=version ...] > /app/tool-inventory.json
#
# PINNED_TSV lists the binaries the tools stage pinned, one "name<TAB>version
# [<TAB>path]" per line. The name=version arguments add tools pinned in the
# runtime stage (bbot, Playwright). The apt packages are read with dpkg-query.
# Nothing here runs a tool except node --version; list_tools itself never runs
# one. Requires jq.
set -eu

pinned="$1"
base="$2"
shift 2
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

cat "$pinned" >>"$tmp"
for kv in "$@"; do
	printf '%s\t%s\n' "${kv%%=*}" "${kv#*=}" >>"$tmp"
done

# binary:package for the tools the runtime stage installs with apt.
for pair in \
	nmap:nmap hydra:hydra john:john hashcat:hashcat ncrack:ncrack \
	ssh-audit:ssh-audit sshpass:sshpass nc:netcat-openbsd telnet:inetutils-telnet \
	arp-scan:arp-scan arping:arping fping:fping netdiscover:netdiscover whois:whois dig:dnsutils \
	scapy:python3-scapy \
	impacket-secretsdump:python3-impacket impacket-wmiexec:python3-impacket \
	impacket-rpcdump:python3-impacket impacket-samrdump:python3-impacket impacket-netview:python3-impacket \
	smbclient:smbclient rpcclient:smbclient smbcacls:smbclient nmblookup:samba-common-bin net:samba-common-bin \
	ldapsearch:ldap-utils \
	curl:curl wget:wget git:git jq:jq openssl:openssl sqlite3:sqlite3 xxd:xxd \
	chromium:chromium; do
	bin="${pair%%:*}"
	pkg="${pair#*:}"
	if ver="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)" && [ -n "$ver" ]; then
		printf '%s\t%s\t\t%s\n' "$bin" "$ver" "$pkg" >>"$tmp"
	fi
done
if command -v node >/dev/null 2>&1; then
	printf 'node\t%s\n' "$(node --version)" >>"$tmp"
fi
if command -v python3 >/dev/null 2>&1; then
	printf 'python3\t%s\n' "$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" >>"$tmp"
fi

jq -R -s --arg base "$base" '
  split("\n")
  | map(select(length > 0) | split("\t")
        | {name: .[0], version: .[1]}
          + (if (.[2] // "") != "" then {path: .[2]} else {} end)
          + (if (.[3] // "") != "" then {package: .[3]} else {} end))
  | {generated_by: "Dockerfile", base_version: $base, tools: .}
' "$tmp"
