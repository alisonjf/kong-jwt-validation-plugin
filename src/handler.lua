-- JWT verification module
-- Adapted version of x25/luajwt for Kong. It provides various improvements and
-- an OOP architecture allowing the JWT to be parsed and verified separately,
-- avoiding multiple parsings.
--
-- @see https://github.com/x25/luajwt

local BasePlugin = require "kong.plugins.base_plugin"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"


local type = type
local time = ngx.time
local re_gmatch = ngx.re.gmatch
local error = error
local insert = table.insert
local tostring = tostring
local setmetatable = setmetatable
local getmetatable = getmetatable

local JwtValidationHandler = BasePlugin:extend()


local err_list_mt = {}


local function add_error(errors, k, v)
  if not errors then
    errors = {}
  end

  if errors and errors[k] then
    if getmetatable(errors[k]) ~= err_list_mt then
      errors[k] = setmetatable({errors[k]}, err_list_mt)
    end

    insert(errors[k], v)
  else
    errors[k] = v
  end

  return errors
end
--[[
  JWT public interface
]]--

--- Verify id and exp claims
-- Claims are verified by type and a check.
-- @return A boolean indicating true if no errors zere found
-- @return A list of errors
local function verify_claims(claims)
  local errors

  local id = claims["id"]
  if id == nil then
    errors = add_error(errors, "id", "is not present")  
  elseif type(id) ~= "string" then
    errors = add_error(errors, "id", "must be a string")
  else
    kong.service.request.set_header("x-user-id", id)
  end

  local exp = claims["exp"]
  if exp == nil then
    errors = add_error(errors, "exp", "is not present")  
  elseif type(exp) ~= "number" then
    errors = add_error(errors, "exp", "must be a number")
  end

  return errors == nil, errors
end


--- Retrieve a JWT in a request.
-- Checks for the JWT in the `Authorization` header.
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token()
    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
    end
end

local function do_authentication(conf)
    -- Retrieve token
    local token, err = retrieve_token()
    if err then
        kong.log.err(err)
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    local token_type = type(token)
    if token_type ~= "string" then
        if token_type == "nil" then
            return false, { status = 401, message = "Unauthorized" }
        elseif token_type == "table" then
            return false, { status = 401, message = "Multiple tokens provided" }
        else
            return false, { status = 401, message = "Unrecognizable token" }
        end
    end

    -- Decode token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return false, { status = 401, message = "Bad token; " .. tostring(err) }
    end

    -- Verify algorithim
    if jwt.header.alg ~= (conf.algorithm or "HS256") then
        return false, {status = 403, message = "Invalid algorithm"}
    end

    -- Verify the JWT registered claims
    local ok_claims, errors = verify_claims(jwt.claims)
    if not ok_claims then
        return false, { status = 401, message = "Token claims invalid: " .. table_to_string(errors) }
    end

    -- Verify expiration
    local exp = jwt.claims["exp"]
    if exp <= time() then
      return false, { status = 403, message = "Token expired" }
    end

    local verified_signature = jwt:verify_signature(conf.signature_key)
    if not verified_signature then
      kong.log.err("Invalid signature")
      return false, { status = 401, message = "Invalid token signature" }
    end

    return true
end

function JwtValidationHandler:new()
    JwtValidationHandler.super.new(self, "jwt-validation")
end

function JwtValidationHandler:access(conf)
    JwtValidationHandler.super.access(self)

    -- check if preflight request and whether it should be authenticated
    if kong.request.get_method() == "OPTIONS" then
        return
    end

    local ok, err = do_authentication(conf)
    if not ok then
      return kong.response.exit(err.status, err.errors or { message = err.message })
    end
end


return JwtValidationHandler