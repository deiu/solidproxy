# solidproxy

[![](https://img.shields.io/badge/project-Solid-7C4DFF.svg?style=flat-square)](https://github.com/solid/solid)
[![Build Status](https://travis-ci.org/solid/solidproxy.svg?branch=master)](https://travis-ci.org/solid/solidproxy)
[![Coverage Status](https://coveralls.io/repos/github/solid/solidproxy/badge.svg?branch=master)](https://coveralls.io/github/solid/solidproxy?branch=master)

Proxy server with authentication (for WebID-TLS delegation) that can be used as a microservice along a Solid server.

## Installation

`go get -u github.com/solid/solidproxy/bin`

## Configuration

Solidproxy uses environment variables (for docker compatibility).

* `SOLIDPROXY_VERBOSE` [default false] -- enables logging to `stderr`
* `SOLIDPROXY_INSECURE` [default false] -- accept bad certificates (self-signed, expired, etc.) when connecting to remore servers
* `SOLIDPROXY_PROXYPORT` [default 3129]-- the default port for the proxy service
* `SOLIDPROXY_AGENTPORT` [default 3200]-- the default port for the agent WebID service
* `SOLIDPROXY_AGENT` -- the URL (WebID) of the agent (in case it's on a different server). This is important if you want to use the proxy for delegation of authenticated requests.
* `SOLIDPROXY_USER` -- the URL (WebID) of the User on whose behalf the request is being made (e.g. Bob's WebID)
* `SOLIDPROXY_TLSKEY` -- path to the TLS key file (using PEM format)
* `SOLIDPROXY_TLSCERT` -- path to the TLS cert file (using PEM format)
* `SOLIDPROXY_DISABLEPROXYTLS` -- disable HTTPS for the proxy service (!!! you should only do this if you run the proxy on localhost only !!!)

***Example:***

```
export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_INSECURE="1"

export SOLIDPROXY_PROXYPORT="3129"
export SOLIDPROXY_AGENTPORT="3200"

export SOLIDPROXY_AGENT="https://example.org:3200/webid#me"
export SOLIDPROXY_USER="https://bob.com/profile#me"

export SOLIDPROXY_TLSKEY="test_key.pem"
export SOLIDPROXY_TLSCERT="test_cert.pem"

export SOLIDPROXY_DISABLEPROXYTLS="1"
```

### User profile configuration

For the delegated authentication to work, you need to indicate that you trust and use a third party agent to authenticate and perform requests on your behalf.

This is just a simple matter of adding the following triple to your WebID profile:

```
<https://bob.com/profile#me> <http://www.w3.org/ns/auth/acl#delegates> <http://example.org:3200/webid#me> .
```

This triple says that you *delegate* the agent with the WebID `http://example.org:3200/webid#me`.

## Usage

The app spawns two servers, one that serves the proxy on port `3129` by default (i.e. `example.org:3129/proxy`), and another one on port `3200` that serves the agent's WebID profile for authenticated requests (i.e. `example.org:3200/webid`).

### Running as a micro-service

If you want to use the proxy, your Solid server needs to forward requests to the following URL:

`https://example.org:3129/proxy?uri=https://alice.com/foo/bar`

Say your Solid is available at `https://bob.com/`. You need to configure it so that it forwards all requests it receives at `https://bob.com/proxy` to the solidproxy server running at `https://bob.com:3129/proxy`.