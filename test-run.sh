#!/bin/sh

export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_PORT="3129"
export SOLIDPROXY_AGENT="http://example.org:3129/webid#me"
export SOLIDPROXY_USER="http://user.com/profile#me"

go run bin/*.go
