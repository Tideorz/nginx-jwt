# JWT Auth for Nginx

**nginx-jwt** is a [Lua](http://www.lua.org/) script for the [Nginx](http://nginx.org/) server (running the [HttpLuaModule](http://wiki.nginx.org/HttpLuaModule)) that will allow you to use Nginx as a reverse proxy in front of your existing set of HTTP services and secure them (authentication/authorization) using a trusted [JSON Web Token (JWT)](http://jwt.io/) in the `Authorization` request header, having to make little or no changes to the backing services themselves.

This project is forked based on auth0/nginx-jwt.

## Contents
- [Key Features](#key-features)
- [Install](#install)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)

## Key Features

* Secure an existing HTTP service (ex: REST API) using Nginx reverse-proxy and this script
* Authenticate an HTTP request with the verified identity contained with in a JWT
* Optionally, authorize the same request using helper functions for asserting required JWT claims

## Install

> **IMPORTANT**: **nginx-jwt** is a Lua script that is designed to run on Nginx servers that have the [HttpLuaModule](http://wiki.nginx.org/HttpLuaModule) installed. But ultimately its dependencies require components available in the [OpenResty](http://openresty.org/) distribution of Nginx. Therefore, it is recommended that you use **OpenResty** as your Nginx server, and these instructions make that assumption.

Install steps:

1. Check out this respository and deploy its contents to a directory on your Nginx server.
1. Specify this directory's path using ngx_lua's [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive:  
    ```lua
    # nginx.conf:

    http {
        lua_package_path "/path/to/lua/scripts;;";
        ...
    }
    ```

## Configuration

> At the moment, `nginx-jwt` only supports symmetric keys (`alg` = `hs256`), which is why you need to configure your server with the shared JWT secret below.

1. Export the `JWT_SECRET` environment variable on the Nginx host, setting it equal to your JWT secret.  Then expose it to Nginx server:  
    ```lua
    # nginx.conf:

    env JWT_SECRET;
    ```
1. If your JWT secret is Base64 (URL-safe) encoded, export the `JWT_SECRET_IS_BASE64_ENCODED` environment variable on the Nginx host, setting it equal to `true`.  Then expose it to Nginx server:  
    ```lua
    # nginx.conf:

    env JWT_SECRET_IS_BASE64_ENCODED;
    ```

## Usage

Now we can start using the script in reverse-proxy scenarios to secure our backing service.  This is done by using the [access_by_lua](https://github.com/openresty/lua-nginx-module#access_by_lua) directive to call the `nginx-jwt` script's [`auth()`](#auth) function before executing any [proxy_* directives](http://nginx.org/en/docs/http/ngx_http_proxy_module.html):

```lua
# nginx.conf:

server {
    location /{
        access_by_lua '
            local jwt = require("nginx-jwt")
            local configs = require("configs")
            jwt.auth(configs)
        ';

        proxy_pass http://my-backend.com$uri;
    }
}
```

Update lua/configs.lua with your own criteria

configs is a lua table
it is a list of config tables in order, first matched uri will be in effect and all remaining configs will be ignored
the config table is consisted of following values
- uri: the uri pattern
- action:   possible values are 
   -  "pass":  no auth is checked
   -  "redirect":  when auth is not valid, redirect to redirect_url
   -  "deny":  when auth is not valid, deny access
- claim_specs:   please refer to the following section 
- redirect_url:   url used when redirect is needed
- fields:  fields(payloads) that needs to be passed along in header with X- prefix
l

```lua
local configs = {
    -- config example
    {
        uri = "^/secure_this",
        action = "deny",
        claim_specs = {},
        redirect_url = "", 
        fields = {"sub"}
    },

    {
        uri = "^/url/pattern/",
        action = "redirect",
        claim_specs = {},
        redirect_url = function () return "https://redirect.domain.com/?redirect_url="..ngx.escape_uri("https://"..ngx.var.http_host..ngx.var.request_uri) end,
        fields = {"user_id"}
    },
    -- default to pass
    {
        uri = "^/",
        action = "pass"
    }
}
```


If you attempt to cURL the above `/secure_this` endpoint, you're going to get a `401` response from Nginx since it requires a valid JWT to be passed:

```bash
curl -i http://your-nginx-server/secure_this
```

```
HTTP/1.1 401 Unauthorized
Server: openresty/1.7.7.1
Date: Sun, 03 May 2015 18:05:00 GMT
Content-Type: text/html
Content-Length: 200
Connection: keep-alive

<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>openresty/1.7.7.1</center>
</body>
</html>
```

To create a valid JWT, we've included a handy tool that will generate one given a payload and a secret.  The payload must be in JSON format and at a minimum should contain a `sub` (subject) element.  The following command will generate a JWT with an arbitrary payload and the specific secret used by the proxy:

```bash
test/sign '{"sub": "flynn"}' 'My JWT secret'
```

```
Payload: { sub: 'flynn' }
Secret: JWTs are the best!
Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwZXRlIiwiaWF0IjoxNDMwNjc3NjYzfQ.Zt4qnQyljbqLvAN7BQSuu14z5PjKcPpZZY85hDFVN3E
```

You can then use the above `Token` (the JWT) and call the Nginx server's `/secure_this` endpoint again:

```bash
curl -i http://your-nginx-server/secure_this -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwZXRlIiwiaWF0IjoxNDMwNjc3NjYzfQ.Zt4qnQyljbqLvAN7BQSuu14z5PjKcPpZZY85hDFVN3E'
```

```
HTTP/1.1 200 OK
Server: openresty/1.7.7.1
Date: Sun, 03 May 2015 18:34:18 GMT
Content-Type: text/plain
Content-Length: 47
Connection: keep-alive
X-sub: flynn
X-Powered-By: Express
ETag: W/"2f-8fc49de2"

The reverse-proxied response!
```

In this case the Nginx server has authorized the caller and performed a reverse proxy call to the backing service's endpoint.  
Notice that a header named "X-sub" with value flynn will be passed to app server as well, as configured in the 'fields'

If you visit http://your-nginx-server/url/pattern without a valid JWT, you will be redirected to the url defined in the redirect_url in configs.

Otherwise for any other urls under http://your-nginx-server, there is no JWT check


### claim_specs

Authenticates the current request, requiring a JWT bearer token in the `Authorization` request header.  Verification uses the value set in the `JWT_SECRET` (and optionally `JWT_SECRET_IS_BASE64_ENCODED`) environment variables.

If authentication succeeds, then by default the current request is authorized by virtue of a valid user identity.  More specific authorization can be accomplished via the optional `claim_specs` parameter.  If provided, it must be a Lua [Table](http://www.lua.org/pil/2.5.html) where each key is the name of a desired claim and each value is a [pattern](http://www.lua.org/pil/20.2.html) that can be used to test the actual value of the claim.  If your claim value is more complex that what a pattern can handle, you can pass an anonymous function instead that has the signature `function (val)` and returns a truthy value (or just `true`) if `val` is a match.  You can also use the [`table_contains`](#table_contains) helper function to easily check for an existing value in an array table.

For example if we wanted to ensure that the JWT had an `aud` (Audience) claim value that started with `foo:` and a `roles` claim that contained a `marketing` role, then the `claim_specs` parameter might look like this:

```lua
    {
        aud="^foo:",
        role=function (val) return jwt.table_contains(val, "marketing") end
    }
```
and if our JWT's payload of claims looked something like this, the above call would succeed:

```json
{
    "aud": "foo:user",
    "roles": [ "sales", "marketing" ]
}
```

**NOTE:** the **auth** function should be called within the [access_by_lua](https://github.com/openresty/lua-nginx-module#access_by_lua) or [access_by_lua_file](https://github.com/openresty/lua-nginx-module#access_by_lua_file) directive so that it can occur before the Nginx **content** [phase](http://wiki.nginx.org/Phases).



## API Reference

### table_contains

Syntax: `table_contains(table, item)`

A helper function that checks to see if `table` (a Lua [Table](http://www.lua.org/pil/2.5.html)) contains the specified `item`.  If it does, the function returns `true`; otherwise `false`.  This is particularly helpful for checking for a value in an array:

```lua
array = { "foo", "bar" }
table_contains(array, "foo") --> true
```
