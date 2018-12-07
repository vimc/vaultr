##' Look up an environment variable.  This is a wrapper around
##' \code{\link{Sys.getenv}} but designed to ease non-interactive use
##' of vault.
##'
##' @title Look up an environment variable
##'
##' @param name The name of the environment variable.  Typically this
##'   is an upper-case name, with words separated by underscores
##'
##' @param mode Mode to set the variable to.  This can be one of
##'   "character" (the default) or "integer"
##' @export
envvar <- function(name, mode = "character") {
  value <- Sys_getenv(name, NULL, mode)
  if (is.null(value)) {
    stop(sprintf("Environment variable '%s' was not set", name),
         call. = FALSE)
  }
  value
}
