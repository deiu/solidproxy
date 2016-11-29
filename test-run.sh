#!/bin/sh

export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_PORT="3129"
export SOLIDPROXY_WEBID="http://128.30.9.62:3129/webid#me"

go run bin/*.go
