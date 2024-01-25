# JWT AntPath

![workflow build](https://github.com/x-ream/traefik-plugin-jwt-antpath/workflows/go.yml/badge.svg)

JWT AntPath is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which verify JWT excludes configured path, and add payload to header

## Configuration

## Static

```toml
[experimental.plugins.jwtant]
    modulename = "github.com/x-ream/traefik-plugin-jwt-antpath"
    version = "v0.0.2"
```

## Dynamic

To configure the `JWT AntPath` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in 
your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates
and uses the `JWT AntPath` middleware plugin to verify token and add payload to header of all HTTP requests exclude path starting with `/foo`. 

```toml
[http.routers]
  [http.routers.my-router]
    rule = "Host(`localhost`)"
    middlewares = ["jwtant"]
    service = "my-service"

# Very jwt exclude all paths starting with /foo
[http.middlewares]
  [http.middlewares.foo.plugin.jwtant]
    secureKey = "my-secret-key"
    headerKey =  "Authorization"  
    paths = ["/foo/**", "/*/goods/**"]

[http.services]
  [http.services.my-service]
    [http.services.my-service.loadBalancer]
      [[http.services.my-service.loadBalancer.servers]]
        url = "http://127.0.0.1"
```
