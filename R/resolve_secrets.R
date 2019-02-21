#' Use vault to resolve secrets.
#' 
#' Sets up a vault client via call to \code{\link{vault_client}} and resolves
#' secrets specified by the form VAULT:<path to secret>:<key to get>.
#'
#' @param x List of properties values of which may be vault secrets of the form
#' VAULT:<path to secret>:<key to get>. Any values which don't match pattern
#' of a secret are ignored and returned as is.
#' @param ... Args to be passed to \code{\link{vault_client}} call.
#' @param login Login method to be passed to call to \code{\link{vault_client}}.
#'
#' @return List of properties with any vault secrets resolved.
#' @export
#' 
#' @examples
#' \dontrun{
#' srv <- vaultr::vault_test_server()
#' cl <- srv$client()
#' cl$write("/secret/users/alice", list(password = "ALICE"))
#' x <- list(name = "alice",
#'   password = "VAULT:/secret/users/alice:password")
#' withr::with_envvar(c(VAULTR_AUTH_METHOD = "token", VAULT_TOKEN = srv$token),
#'   x <- resolve_secrets(x, addr = srv$addr)
#' )
#' }
#' 
#' 
resolve_secrets <- function(x, ..., login = TRUE) {
  re <- "^VAULT:(.+):(.+)"
  if (is.list(x)) {
    i <- vlapply(x, function(el) is.character(el) && grepl(re, el))
    if (any(i)) {
      x[i] <- resolve_secrets(vcapply(x[i], identity), ...)
    }
  } else {
    i <- grepl(re, x)
    if (any(i)) {
      loadNamespace("vaultr")
      vault <- vaultr::vault_client(login = login, ...)
      key <- unname(sub(re, "\\1", x[i]))
      field <- unname(sub(re, "\\2", x[i]))
      x[i] <- unname(Map(vault$read, key, field))
    }
  }
  x
}