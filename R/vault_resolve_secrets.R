##' Use vault to resolve secrets.  This is a convenience function that
##' wraps a pattern that we have used in a few applications of vault.
##' The idea is to allow replacement of data in configuration with
##' special strings that indicate that the string refers to a vault
##' secret.  This function resolves those secrets.
##'
##' For each element of the data, if a string matches the form:
##'
##' \preformatted{
##'   VAULT:<path to secret>:<field>
##' }
##'
##' then it will be treated as a vault secret and resolved.  The
##' \code{<path to get>} will be something like
##' \code{/secret/path/password} and the \code{<field>} the name of a
##' field in the key/value data stored at that path.  For example,
##' suppose you ave the data \code{list(username = "alice", password =
##' "s3cret!")} stored at \code{/secret/database/user}, then the
##' string
##'
##' \preformatted{
##'   VAULT:/secret/database/user:password
##' }
##'
##' would refer to the value \code{s3cret!}
##'
##' @param x List of values, some of which may refer to vault secrets
##'   (see Details for pattern).  Any values that are not strings or
##'   do not match the pattern of a secret are left as-is.
##'
##' @param ... Args to be passed to \code{\link{vault_client}} call.
##'
##' @param login Login method to be passed to call to
##'   \code{\link{vault_client}}.
##'
##' @return List of properties with any vault secrets resolved.
##'
##' @export
##'
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##'
##' if (!is.null(server)) {
##'   cl <- server$client()
##'   # The example from above:
##'   cl$write("/secret/database/user",
##'            list(username = "alice", password = "s3cret!"))
##'
##'   # A list of data that contains a mix of secrets to be resolved
##'   # and other data:
##'   x <- list(user = "alice",
##'             password = "VAULT:/secret/database/user:password",
##'             port = 5678)
##'
##'   # Explicitly pass in the login details and resolve the secrets:
##'   vaultr::vault_resolve_secrets(x, login = "token", token = server$token,
##'                                 addr = server$addr)
##'
##'   # Alternatively, if appropriate environment variables are set
##'   # then this can be done more easily:
##'   if (requireNamespace("withr", quietly = TRUE)) {
##'     env <- c(VAULTR_AUTH_METHOD = "token",
##'              VAULT_TOKEN = server$token,
##'              VAULT_ADDR = server$addr)
##'     withr::with_envvar(env, vault_resolve_secrets(x))
##'   }
##' }
vault_resolve_secrets <- function(x, ..., login = TRUE) {
  re <- "^VAULT:(.+):(.+)"
  if (is.list(x)) {
    i <- vlapply(x, function(el) is.character(el) && grepl(re, el))
    if (any(i)) {
      x[i] <- vault_resolve_secrets(vcapply(x[i], identity),
                                    ..., login = login)
    }
  } else {
    i <- grepl(re, x)
    if (any(i)) {
      vault <- vault_client(login = login, ...)
      key <- unname(sub(re, "\\1", x[i]))
      field <- unname(sub(re, "\\2", x[i]))
      x[i] <- unname(Map(vault$read, key, field))
    }
  }
  x
}
