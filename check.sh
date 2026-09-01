#!/bin/sh
# Checks each node's DoH and DoT endpoints and reports to uptime-kuma push
# monitors.
#
# Why not uptime-kuma's built-in HTTP(s) monitor: dnsdist 1.9+ enforces
# RFC 8484 section 5.2 and rejects DoH over HTTP/1.1 with a 400. Uptime Kuma's
# HTTP monitor uses axios, which is HTTP/1.1 only, so it cannot check DoH
# against a current dnsdist. kdig speaks both DoH and DoT and reports the
# negotiated HTTP version, so this asserts HTTP/2 explicitly rather than just a
# 2xx status. There is also no built-in monitor type that does real DoT.
set -u

KUMA="${KUMA:-http://uptime-kuma-svc.uptime-kuma.svc.cluster.local}"
DOMAIN="${DOMAIN:-bancuh.com}"
NODES="${NODES:-}"
QNAME="${QNAME:-careers.opendns.com}"
TIMEOUT="${TIMEOUT:-8}"

[ -n "$NODES" ] || { echo "FATAL: NODES is empty"; exit 1; }

rc=0

push() { # token status msg ping_ms
  [ -n "${1:-}" ] || { echo "  skip push: no token for '$3'"; return 0; }
  curl -fsS -m 10 -o /dev/null -G "$KUMA/api/push/$1" \
    --data-urlencode "status=$2" \
    --data-urlencode "msg=$3" \
    --data-urlencode "ping=$4" || { echo "  WARN: push failed ($2: $3)"; rc=1; }
}

check() { # short_name proto
  _n="$1"; _proto="$2"
  _host="$_n.$DOMAIN"
  _key=$(echo "$_n" | tr 'a-z-' 'A-Z_' | tr -cd 'A-Z0-9_')
  eval "_token=\${TOKEN_${_key}_$(echo "$_proto" | tr 'a-z' 'A-Z'):-}"

  # The trailing dot on @host matters: a Kubernetes pod's resolv.conf carries
  # ndots:5 and search domains, and if one answers NOERROR/no-data musl's
  # getaddrinfo gives up rather than trying the absolute name. dig copes,
  # kdig does not.
  # +tls-ca/+tls-hostname verify the server certificate, so an expired or
  # stale cert is caught rather than silently accepted.
  case "$_proto" in
    doh) _out=$(kdig +https +tls-ca +tls-hostname="$_host" +timeout="$TIMEOUT" +retry=0 @"$_host." "$QNAME" A 2>&1) ;;
    dot) _out=$(kdig +tls   +tls-ca +tls-hostname="$_host" +timeout="$TIMEOUT" +retry=0 @"$_host." "$QNAME" A 2>&1) ;;
    *)   echo "  bad proto: $_proto"; rc=1; return ;;
  esac

  _ms=$(echo "$_out" | sed -n 's/.* in \([0-9.]*\) ms.*/\1/p' | head -1)
  [ -n "$_ms" ] || _ms=0

  if ! echo "$_out" | grep -q "status: NOERROR"; then
    _msg="$_proto: $(echo "$_out" | grep -iE 'error|warning' | head -1 | sed 's/^;; *//' | cut -c1-110)"
    echo "DOWN $_host $_msg"
    push "$_token" down "$_msg" "$_ms"
    return
  fi

  if [ "$_proto" = doh ] && ! echo "$_out" | grep -q "HTTP/2"; then
    echo "DOWN $_host doh: did not negotiate HTTP/2"
    push "$_token" down "doh: did not negotiate HTTP/2" "$_ms"
    return
  fi

  echo "UP $_host $_proto ${_ms}ms"
  push "$_token" up "$_proto ok" "$_ms"
}

for n in $NODES; do
  check "$n" doh
  check "$n" dot
done

exit $rc
