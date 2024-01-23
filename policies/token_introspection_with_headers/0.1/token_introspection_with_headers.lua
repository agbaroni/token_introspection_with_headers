local policy = require('apicast.policy')
local _M = policy.new('Token Introspection Policy With Claim Extraction','0.1')

-- json parser
local cjson = require('cjson.safe')

-- http objects for introspection call
local http_authorization = require 'resty.http_authorization'
local http_ng = require 'resty.http_ng'
local user_agent = require 'apicast.user_agent'
local resty_env = require('resty.env')
local resty_url = require('resty.url')
-- cache
local tokens_cache = require('tokens_cache')

local tonumber = tonumber
local insert = table.insert

local new = _M.new
-- set a noop cache dummy function for disabling the cache
local noop = function() end
local noop_cache = { get = noop, set = noop }

-- templating engine for claim extraction
local TemplateString = require 'apicast.template_string'
local default_value_type = 'plain'


-- header manipulation functions

local function new_header_value(current_value, value_to_add)
  if not value_to_add then return current_value end

  local new_value = current_value or {}

  if type(new_value) == 'string' then
    new_value = { new_value }
  end

  insert(new_value, value_to_add)
  return new_value
end

local function push_request_header(header_name, value, req_headers)
  local new_value = new_header_value(req_headers[header_name], value)
  ngx.log(ngx.DEBUG, "pushing request header " .. header_name .. " with value: ", value)
  ngx.req.set_header(header_name, new_value)
end

local function set_request_header(header_name, value)
  ngx.log(ngx.DEBUG, "setting request header " .. header_name .. " with value: ", value)
  ngx.req.set_header(header_name, value)
end

local function add_request_header(header_name, value, req_headers)
  if req_headers[header_name] then
    ngx.log(ngx.DEBUG, "adding request header " .. header_name .. " with value: ", value)
    push_request_header(header_name, value, req_headers)
  end
end

-- utility function to convert values
local function _convert_value_to_table(value)
  if type(value) == "string" then
    return { value }
  end

  return value
end

local header_functions = {
    push = push_request_header,
    add = add_request_header,
    set = set_request_header,
}
-- response processing and header setting function
local function process_introspection_response(introspect_token_response,headers_config)
  local req_headers = ngx.req.get_headers() or {}

  for _, header_config in ipairs(headers_config) do
    local header_func = header_functions[header_config.op]
    local value = ""

    if header_config.value_type == "plain" then
      value = cjson.encode(_convert_value_to_table(introspect_token_response[header_config.template_string:render()]))
      ngx.log(ngx.DEBUG, 'introspect_token_response[header_config.template_string:render()]:(',header_config.template_string:render(),') ', value)
    else
      value = cjson.encode(_convert_value_to_table(header_config.template_string:render(introspect_token_response)))
      ngx.log(ngx.DEBUG, 'header_config.template_string:render(introspect_token_response):', value)
    end

    header_func(header_config.header, value, req_headers)
  end
  return 
end
-- initialize the header templates

local function build_templates(headers)
  for _, header in ipairs(headers) do
    header.template_string = TemplateString.new(
      header.value, header.value_type or default_value_type)
  end
end
--- token introspection functions

local function create_credential(client_id, client_secret)
  return 'Basic ' .. ngx.encode_base64(table.concat({ client_id, client_secret }, ':'))
end

--- OAuth 2.0 Token Introspection defined in RFC7662.
-- https://tools.ietf.org/html/rfc7662
local function introspect_token(self, token)
  local cached_token_info = self.tokens_cache:get(token)
  if cached_token_info then return cached_token_info end

  --- Parameters for the token introspection endpoint.
  -- https://tools.ietf.org/html/rfc7662#section-2.1
  local res, err = self.http_client.post{self.introspection_url , { token = token, token_type_hint = 'access_token'},
    headers = {['Authorization'] = self.credential}}
  if err then
    ngx.log(ngx.WARN, 'token introspection error: ', err, ' url: ', self.introspection_url)
    return { active = false }
  end

  if res.status == 200 then
    local token_info, decode_err = cjson.decode(res.body) -- lo trasforma in oggetto
    if type(token_info) == 'table' then
      ngx.log(ngx.DEBUG,'introspection response: ', token_info)
      self.tokens_cache:set(token, token_info)
      return token_info
    else
      ngx.log(ngx.ERR, 'failed to parse token introspection response:', decode_err)
      return { active = false }
    end
  else
    ngx.log(ngx.WARN, 'failed to execute token introspection. status: ', res.status)
    return { active = false }
  end
end

-- ability to deny the request before it is sent upstream
function _M:access(context)
  if self.auth_type == "use_3scale_oidc_issuer_endpoint" then
    if not context.proxy.oauth then
      ngx.status = context.service.auth_failed_status
      ngx.say(context.service.error_auth_failed)
      return ngx.exit(ngx.status)
    end

    local components = resty_url.parse(context.service.oidc.issuer_endpoint)
    self.credential = create_credential(components.user, components.password)
    self.introspection_url = context.proxy.oauth.config.token_introspection_endpoint
  end

  if self.introspection_url then
    local authorization = http_authorization.new(ngx.var.http_authorization)
    local access_token = authorization.token
    local introspect_token_response = introspect_token(self, access_token)
    --- Introspection Response must have an "active" boolean value.
    -- https://tools.ietf.org/html/rfc7662#section-2.2
    if not introspect_token_response.active == true then
      ngx.log(ngx.INFO, 'token introspection for access token ', access_token, ': token not active')
      ngx.status = context.service.auth_failed_status
      ngx.say(context.service.error_auth_failed)
      return ngx.exit(ngx.status)
    else
      
      ngx.log(ngx.INFO, 'token introspection for access token ', access_token, ': token active, extracting claims...')
      ngx.log(ngx.INFO, 'token introspection response: ',introspect_token_response)
      process_introspection_response(introspect_token_response,self.headers_config)
    end
  end
end





-- initialize the policy
function _M.new(config)
  local self = new(config)
  self.config = config or {}
  self.introspection_config = config.introspection or {}
  -- token introspection initialization
  self.auth_type = self.introspection_config.auth_type or "client_id+client_secret"
  --- authorization for the token introspection endpoint.
  -- https://tools.ietf.org/html/rfc7662#section-2.2
  if self.auth_type == "client_id+client_secret" then
    self.credential = create_credential(self.introspection_config.client_id or '', self.introspection_config.client_secret or '')
    self.introspection_url = self.introspection_config.introspection_url
  end
  self.http_client = http_ng.new{
    backend = config.client,
    options = {
      headers = {
        ['User-Agent'] = user_agent()
      },
      ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
    }
  }

  local max_cached_tokens = tonumber(self.introspection_config.max_cached_tokens) or 0
  self.caching_enabled = max_cached_tokens > 0

  if self.caching_enabled then
    self.tokens_cache = tokens_cache.new(
      self.introspection_config.max_ttl_tokens, self.introspection_config.max_cached_tokens)
  else
    self.tokens_cache = noop_cache
  end
  -- header section initialization
  self.headers_config = config.headers or {}

  build_templates(self.headers_config)
  
  return self

end



--[[
function _M:init()
  -- do work when nginx master process starts
end

function _M:init_worker()
  -- do work when nginx worker process is forked from master
end

function _M:rewrite()
  -- change the request before it reaches upstream
end

function _M:access()
  -- ability to deny the request before it is sent upstream
end

function _M:content()
  -- can create content instead of connecting to upstream
end

function _M:post_action()
  -- do something after the response was sent to the client
end

function _M:header_filter()
  -- can change response headers
end

function _M:body_filter()
  -- can read and change response body
  -- https://github.com/openresty/lua-nginx-module/blob/master/README.markdown#body_filter_by_lua
end

function _M:log()
  -- can do extra logging
end

function _M:balancer()
  -- use for example require('resty.balancer.round_robin').call to do load balancing
end
]]
return _M

