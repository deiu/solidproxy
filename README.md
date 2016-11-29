# solidproxy
Proxy server with authentication (for WebID-TLS delegation) that can be used as a microservice along a Solid server.

## Installation

`go get -u github.com/solid/solidproxy/bin`

## Configuration

Solidproxy uses environment variables (for docker compatibility).

* `SOLIDPROXY_VERBOSE` enables logging to `stderr`
* `SOLIDPROXY_PORT` sets the default port for the service
* `SOLIDPROXY_WEBID` sets the URL (WebID) of the agent. This is important if you want to use the proxy for delegation of authenticated requests.

***Example:***

```
export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_PORT="3129"
export SOLIDPROXY_WEBID="http://example.org:3129/webid#me"
```

## Usage

The server currently uses two routes, one that serves the proxy (i.e. `/proxy`), and another one that serves the agent's WebID profile for authenticated requests (i.e. `/webid`).

### Running as a micro-service

If you want to use the proxy, your Solid server needs to forward requests to the following URL:

`http://example.org:3129/proxy?uri=https://alice.com/foo/bar`

Say your Solid is available at `https://bob.com/`. You need to configure it so that it forwards all requests it receives at `https://bob.com/proxy` to the solidproxy server running at `https://bob.com:3129/proxy`.