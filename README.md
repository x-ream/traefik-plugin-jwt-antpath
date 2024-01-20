# JWT Ex Path

[![Build Status](https://github.com/x-ream/traefik-plugin-jwt-ex-pathworkflows/Main/badge.svg?branch=master)](https://github.com/x-ream/traefik-plugin-jwt-ex-pathactions)

JWT Ex Path is a middleware plugin for [Traefik](https://github.com/x-ream/traefik) which excludes JWT verification of requests from configured path.

## Configuration

## Static

```toml
[experimental.plugins.blockpath]
    modulename = "github.com/x-ream/traefik-plugin-jwt-ex-path"
    version = "v0.0.1"
```

## Dynamic

To configure the `JWT Ex Path` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in 
your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates
and uses the `JWT Ex Path` middleware plugin to block all HTTP requests with a path starting with `/foo`. 

```toml
[http.routers]
  [http.routers.my-router]
    rule = "Host(`localhost`)"
    middlewares = ["traefik-plugin-jwt-ex-path"]
    service = "my-service"

# Block all paths starting with /foo
[http.middlewares]
  [http.middlewares.ex-foo.plugin.traefik-plugin-jwt-ex-path]
    secureKey = "my-secret-key"
    headerKey =  "Authorization"  
    paths = ["/foo/**", "/*/goods/**"]

[http.services]
  [http.services.my-service]
    [http.services.my-service.loadBalancer]
      [[http.services.my-service.loadBalancer.servers]]
        url = "http://127.0.0.1"
```
