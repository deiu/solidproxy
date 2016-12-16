# solidproxy

[![](https://img.shields.io/badge/project-Solid-7C4DFF.svg?style=flat-square)](https://github.com/solid/solid)
[![Build Status](https://travis-ci.org/solid/solidproxy.svg?branch=master)](https://travis-ci.org/solid/solidproxy)
[![Coverage Status](https://coveralls.io/repos/github/solid/solidproxy/badge.svg?branch=master)](https://coveralls.io/github/solid/solidproxy?branch=master)

Proxy server with authentication (for WebID-TLS delegation) that can be used as a micro-service along a Solid server.

## Installation

### Using the source code on Github

`go get -u github.com/solid/solidproxy/proxy-server`

### Using the Docker image

***Note:*** The docker image is configured to run on HTTP by default. This means that you should set up a reverse proxy using Nginx or Apache, and handle the HTTPS configuration there.

First, you have to pull the docker image:

	docker pull solidproject/solidproxy

Next, create a file called `env.list` in which you set the configuration variables (read below to find more about them).

Once you're done with the config, save the file and run the docker image:

	docker run --env-file ./env.list -p <host_proxyport>:<container_proxyport> -p <host_agentport>:<container_agentport> solidproject/solidproxy

Replace the above port values with your own port numbers from your configuration.

## Configuration for standalone server

Solidproxy uses environment variables (for docker compatibility).

* `SOLIDPROXY_VERBOSE` [default false] -- enables logging to `stderr`
* `SOLIDPROXY_INSECURE` [default false] -- accept bad certificates (self-signed, expired, etc.) when connecting to remore servers
* `SOLIDPROXY_PROXYPORT` [default 3129]-- the default port for the proxy service
* `SOLIDPROXY_AGENTPORT` [default 3200]-- the default port for the agent WebID service
* `SOLIDPROXY_AGENT` -- the URL (WebID) of the agent (in case it's on a different server). This is important if you want to use the proxy for delegation of authenticated requests.
* `SOLIDPROXY_ENABLETLS` -- enable HTTPS for the proxy service
* `SOLIDPROXY_TLSKEY` -- path to the TLS key file (using PEM format)
* `SOLIDPROXY_TLSCERT` -- path to the TLS cert file (using PEM format)

***Example:***

```
export SOLIDPROXY_VERBOSE="1"
export SOLIDPROXY_INSECURE="1"

export SOLIDPROXY_PROXYPORT="3129"
export SOLIDPROXY_AGENTPORT="3200"

export SOLIDPROXY_AGENT="https://example.org:3200/webid#me"

export SOLIDPROXY_ENABLETLS="1"
export SOLIDPROXY_TLSKEY="test_key.pem"
export SOLIDPROXY_TLSCERT="test_cert.pem"
```

### User profile configuration

For the delegated authentication to work, you need to indicate that you trust and use a third party agent to authenticate and perform requests on your behalf.

This is just a simple matter of adding the following triple to your WebID profile:

```
<https://bob.com/profile#me> <http://www.w3.org/ns/auth/acl#delegates> <http://example.org:3200/webid#me> .
```

This triple says that you *delegate* the agent with the WebID `https://example.org:3200/webid#me`.

## Usage

The app spawns two servers, one that serves the proxy on port `3129` by default (i.e. `example.org:3129/proxy`), and another one on port `3200` that serves the agent's WebID profile for authenticated requests (i.e. `example.org:3200/webid`).

### Running as a micro-service

If you want to use the proxy, your Solid server needs to forward requests to the following URL:

`https://example.org:3129/proxy?uri=https://alice.com/foo/bar`

Say your Solid is available at `https://bob.com/`. You need to configure it so that it forwards all requests it receives at `https://bob.com/proxy` to the solidproxy server running at `https://bob.com:3129/proxy`.

Aditionally, if you want to use the delegation feature of the server, you need to specify the user on whose behalf the request is made. To do this, your server needs to set the `User` header to the WebID of the user.

For example, if your server considers Bob to be authenticated and wants to perform a request on Bob's behalf, then it will set the `User` header to Bob's WebID: `https://bob.com/webid#me` as seen below.

```
GET /proxy?uri=https://alice.com/foo/bar HTTP/1.1
Host: example.org:3129
User: https://bob.com/webid#me
...
```

### Running as a library

Here is a short example showing how you can use the proxy as a library in your own Go project.

```golang
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/solid/solidproxy"
)

func main() {
	mux := http.NewServeMux()

	// Init logger
	logger := log.New(os.Stderr, "[debug] ", log.Flags()|log.Lshortfile)

	// create a new agent object with its corresponding key pair and profile
	// document and serve it under /agent
	agent, err := solidproxy.NewAgentLocal("http://localhost:8080/agent#me")
	if err != nil {
		log.Println("Error creating new agent:", err.Error())
		return
	}
	// assign logger
	agent.Log = logger
	
	// Skip verifying trust chain for certificates?
	// Use true when dealing with self-signed certs (testing, etc.)
	insecureSkipVerify := true
	// create a new proxy object
	proxy := solidproxy.NewProxy(agent, insecureSkipVerify)
	// assign logger
	proxy.Log = logger

	// init handlers
	handleProxy := http.HandlerFunc(proxy.Handler)
	handleAgent := http.HandlerFunc(agent.Handler)

	// set handlers
	mux.Handle("/proxy", handleProxy) // http://localhost:8080/proxy
	mux.Handle("/agent", handleAgent) // http://localhost:8080/agent

	log.Println("Listening...")
	http.ListenAndServe(":8080", mux)
}
```