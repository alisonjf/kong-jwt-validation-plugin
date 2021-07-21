local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-validation",
  fields = {
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {
          { signature_key = { type = "string", required = true }, },
          { algorithm = { type = "string", default = "HS256" }, },
        },
      },
    },
  },
}