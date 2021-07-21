package = "kong-plugin-jwt-validation"  
version = "1.2-1"

local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "jwt-validation"
supported_platforms = {"linux", "macosx"}

source = {
   url = "git+https://github.com/alisonjf/kong-jwt-validation-plugin.git"
}
description = {
   summary = "A plugin for Kong which adds a custom generated JWT expiration time and user id claim validation",
   homepage = "https://github.com/alisonjf/kong-jwt-validation-plugin.git",
   license = "MIT"
}
dependencies = {}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.jwt-validation.handler"] = "src/handler.lua",
      ["kong.plugins.jwt-validation.schema"] = "src/schema.lua"
   }
}