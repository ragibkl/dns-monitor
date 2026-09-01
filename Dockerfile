FROM alpine:3.23

# knot-utils gives kdig, which speaks both DoH (HTTP/2) and DoT and reports the
# negotiated HTTP version. curl is used only to push results to uptime-kuma.
# These are baked in rather than installed at runtime: doing "apk add" on every
# CronJob tick made the checks depend on the Alpine CDN, and a single failed
# install produced a false "down" within hours of deploying.
RUN apk add --no-cache knot-utils curl

COPY check.sh /usr/local/bin/check.sh

ENTRYPOINT ["/bin/sh", "/usr/local/bin/check.sh"]
