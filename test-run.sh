#!/bin/sh

export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_INSECURE="1"
export SOLIDPROXY_PROXYPORT="3129"
export SOLIDPROXY_AGENTPORT="3200"
export SOLIDPROXY_AGENT="https://localhost:3200/webid#me"
export SOLIDPROXY_USER="https://alice.com/profile#me"

export SOLIDPROXY_TLSKEY="test_key.pem"
export SOLIDPROXY_TLSCERT="test_cert.pem"
export SOLIDPROXY_ENABLEPROXYTLS="1"

go run bin/*.go
