-- configs is a lua table
-- it is a list of config tables in order 
-- the config table is consisted of following values
-- uri: the uri pattern
-- action:   possible values are 
--      "pass":  no auth is checked
--      "redirect":  when auth is not valid, redirect to redirect_url
--      "deny":  when auth is not valid, deny
-- claim_specs:   please refer to https://github.com/auth0/nginx-jwt for its definition
-- redirect_url:   url used when redirect is needed
-- fields:  fields that needs to be passed along in header with X- prefix
local configs = {
    {
        uri = "^/sign/",
        action = "sign",
    },
    {
        uri = "^/verify/",
        action = "verify",
        --redirect_url = function () return "https://redirect.domain.com/?redirect_url="..ngx.escape_uri("https://"..ngx.var.http_host..ngx.var.request_uri) end,
        redirect_url = function () return "http://dev-gnpd-app11.shanghai.mintel.ad/hello_kitty.jpg"  end,
        fields = {"user_id"}
    },
    -- default to pass
    {
        uri = "^/",
        action = "pass"
    }
}
return configs
