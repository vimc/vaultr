vault_client_object <- R6::R6Class(
  "vault_client_object",
  cloneable = FALSE,

  private = list(
    name = NULL,
    description = NULL
  ),

  public = list(
    initialize = function(description) {
      private$name <- sub("^(vault_|vault_client_)", "", class(self)[[1L]])
      private$description <- description
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, private$name, private$description)
    },

    help = function(help_type = NULL) {
      vault_object_help(self, help_type)
    }
  ))


vault_object_help <- function(object, help_type) {
  ## nocov start
  if (!is.null(help_type)) {
    oo <- options(help_type = help_type)
    on.exit(options(oo))
  }
  help(class(object)[[1L]], package = "vaultr")
  ## nocov end
}
