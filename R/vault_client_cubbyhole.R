## For now this is based on the kv1 engine, but we might need to break
## that apart later if full ttl support is set up for kv1.
R6_vault_client_cubbyhole <- R6::R6Class(
  "vault_client_cubbyhole",
  inherit = R6_vault_client_kv1,
  public = list(
    initialize = function(api_client) {
      super$initialize(api_client, "cubbyhole")
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "cubbyhole",
                          "Interact with vault's cubbyhole secret backend")
    },

    custom_mount = function(mount) {
      stop("The cubbyhole secret engine cannot be moved")
    }))
