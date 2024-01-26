# JWT AntPath

![workflow build](https://github.com/x-ream/traefik-plugin-jwt-antpath/actions/workflows/go.yml/badge.svg)

JWT AntPath is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which verify JWT excludes configured path, and add payload to header

## Configuration

## Helm charts values.yml

```yaml
experimental:
  enabled: true
  plugins:
    jwtantpath:
      moduleName: "github.com/x-ream/traefik-plugin-jwt-antpath"
      version: "v0.0.3"
```

## K8s Middleware

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: my-jwtantpath
spec:
  plugin:
    jwtantpath:
      headerKey: "Authorization"
      secureKey: "my-secret-key"
      paths:
        - /base/app-home/**
```

## Static

```toml
[experimental.plugins.jwtantpath]
    modulename = "github.com/x-ream/traefik-plugin-jwt-antpath"
    version = "v0.0.3"
```

## Dynamic

To configure the `JWT AntPath` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in 
your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates
and uses the `JWT AntPath` middleware plugin to verify token and add payload to header of all HTTP requests exclude path starting with `/foo`. 

```toml
[http.routers]
  [http.routers.my-router]
    rule = "Host(`localhost`)"
    middlewares = ["jwtantpath"]
    service = "my-service"

# Very jwt exclude all paths starting with /foo
[http.middlewares]
  [http.middlewares.foo.plugin.jwtantpath]
    secureKey = "my-secret-key"
    headerKey =  "Authorization"  
    paths = ["/foo/**", "/*/goods/**"]

[http.services]
  [http.services.my-service]
    [http.services.my-service.loadBalancer]
      [[http.services.my-service.loadBalancer.servers]]
        url = "http://127.0.0.1"
```
