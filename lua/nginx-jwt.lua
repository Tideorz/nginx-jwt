local jwt = require "resty.jwt"
local cjson = require "cjson"
local basexx = require "basexx"
local secret = os.getenv("JWT_SECRET")

assert(secret ~= nil, "Environment variable JWT_SECRET not set")

if os.getenv("JWT_SECRET_IS_BASE64_ENCODED") == 'true' then
    -- convert from URL-safe Base64 to Base64
    local r = #secret % 4
    if r == 2 then
        secret = secret .. "=="
    elseif r == 3 then
        secret = secret .. "="
    end
    secret = string.gsub(secret, "-", "+")
    secret = string.gsub(secret, "_", "/")

    -- convert from Base64 to UTF-8 string
    secret = basexx.from_base64(secret)
end

local M = {}

function M.auth(configs)
    -- check configs type
    if type(configs) ~= 'table' then
        ngx.log(ngx.STDERR, "Configuration error: configs arg must be a table")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- go through each configured uri and do corresponding checks
    local request_uri = ngx.var.request_uri
    for _, config in ipairs(configs) do
        if string.match(request_uri, config["uri"]) ~= nil then
            local action = config["action"]
            if action == "pass" then
                return
            elseif action == "verify" then
                claim_specs = config["claim_specs"]
                fields = config["fields"]
                if check_jwt(claim_specs, fields) then
                    -- redirect the request if jwt token is valid
                    local redirect_config = config["redirect_url"]
                    -- generate redirect url depend on whether the config is a string or a function
                    local redirect_url = (type(redirect_config) == 'string') and redirect_config or redirect_config()
                    return ngx.redirect(redirect_url)
                else
        	        ngx.exit(ngx.HTTP_UNAUTHORIZED)
                end
            elseif action == "sign" then
                ngx.status = ngx.HTTP_OK
                ngx.req.read_body()
                local jwt_str = ngx.req.get_body_data()
                local jwt_json_obj = cjson.decode(jwt_str)
                local jwt_token = jwt:sign(secret, jwt_json_obj)
                ngx.say(cjson.encode({ token = jwt_token }))
                return ngx.exit(ngx.HTTP_OK)  
            end
        end
    end
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

function check_jwt(claim_specs, fields)
    -- require Authorization request header
    local auth_header = ngx.var.http_Authorization
    local h = ngx.req.get_headers()
    
    if auth_header == nil and jwt_token == nil then
        return false 
    end

    -- require Bearer token or cookie
    local token
    if jwt_token ~= nil then
        token = jwt_token
    else
        _, _, token = string.find(auth_header, "Bearer%s+(.+)")
    end

    if token == nil then
        ngx.log(ngx.WARN, "Missing token")
        return false
    end


    ngx.log(ngx.INFO, "Token: " .. token)

    -- require valid JWT
    local jwt_obj = jwt:verify(secret, token, 0)

    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        return false
    end

    ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))


    -- optionally require specific claims
    if claim_specs ~= nil then
        --TODO: test
        -- make sure they passed a Table
        if type(claim_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: claim_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- process each claim
        local blocking_claim = ""
        for claim, spec in pairs(claim_specs) do
            -- make sure token actually contains the claim
            local claim_value = jwt_obj.payload[claim]
            if claim_value == nil then
                blocking_claim = claim .. " (missing)"
                break
            end

            local spec_actions = {
                -- claim spec is a string (pattern)
                ["string"] = function (pattern, val)
                    return string.match(val, pattern) ~= nil
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    -- convert truthy to true/false
                    if func(val) then
                        return true
                    else
                        return false
                    end
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            -- TODO: test
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a table")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            if not spec_action(spec, claim_value) then
                blocking_claim = claim
                break
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
	    return false
        end
    end


    -- write the X-Auth-UserId header
    for _, field in pairs(fields) do
    	ngx.header["X-"..field] = jwt_obj.payload[field]
    end

    -- pass all the checks
    return true
end

function M.table_contains(table, item)
    for _, value in pairs(table) do
        if value == item then return true end
    end
    return false
end

return M
