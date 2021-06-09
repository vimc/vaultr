##' Base object used by vaultr for all objects
##'
##' @title Base object type
##'
##' @name vault_client_object
##'
##' @importFrom R6 R6Class
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##'
##' if (!is.null(server)) {
##'   client <- vaultr::vault_client(addr = server$addr)
##'   client$operator$format()
##'   client$operator$format(TRUE)
##' }
vault_client_object <- R6::R6Class(
  "vault_client_object",
  cloneable = FALSE,

  private = list(
    name = NULL,
    help_name = NULL,
    description = NULL
  ),

  public = list(
    ##' @description Construct an object
    ##'
    ##' @param description Description for the object, will be printed
    initialize = function(description) {
      private$name <- sub("^(vault_|vault_client_)", "", class(self)[[1L]])
      private$help_name <- class(self)[[1L]]
      private$description <- description
    },

    ##' @description Format method, overriding the R6 default
    ##'
    ##' @param brief Logical, indicating if this is the full format or
    ##'   a brief (one line) format.
    format = function(brief = FALSE) {
      vault_client_format(self, brief, private$name, private$description)
    },

    ##' @description Display help for this object
    help = function() {
      utils::help(private$help_name, package = "vaultr")
    }
  ))


add_const_member <- function(target, name, object) {
  target[[name]] <- object
  lockBinding(name, target)
}
