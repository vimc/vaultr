##' @importFrom R6 R6Class
vault_client_object <- R6::R6Class(
  "vault_client_object",
  cloneable = FALSE,

  private = list(
    name = NULL,
    help_name = NULL,
    description = NULL
  ),

  public = list(
    initialize = function(description) {
      private$name <- sub("^(vault_|vault_client_)", "", class(self)[[1L]])
      private$help_name <- class(self)[[1L]]
      private$description <- description
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, private$name, private$description)
    },

    help = function() {
      utils::help(private$help_name, package = "vaultr")
    }
  ))


add_const_member <- function(target, name, object) {
  target[[name]] <- object
  lockBinding(name, target)
}
