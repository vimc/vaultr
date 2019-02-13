##' @section Methods:
##' \cr\describe{
##' \item{\code{addr}}{
##'   The vault address; this is suitable for using with \code{\link{vault_client}} (read-only).
##' }
##' \item{\code{port}}{
##'   The vault port (read-only).
##' }
##' \item{\code{token}}{
##'   The vault root token, from when the testing vault server was created.  If the vault is rekeyed this will no longer be accurate (read-only).
##' }
##' \item{\code{keys}}{
##'   Key shares from when the vault was initialised (read-only).
##' }
##' \item{\code{cacert}}{
##'   Path to the https certificate, if running in https mode (read-only).
##' }
##' \item{\code{version}}{
##'   Return the server version, as a \code{\link{numeric_version}} object.
##'   \cr\emph{Usage:}\code{version()}
##' }
##' \item{\code{client}}{
##'   Create a new client that can use this server.  The client will be a \code{\link{vault_client}} object.
##'   \cr\emph{Usage:}\code{client(login = TRUE, quiet = TRUE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{login}:   Logical, indicating if the client should login to the server (default is \code{TRUE}).
##'     }
##'
##'     \item{\code{quiet}:   Logical, indicating if informational messages should be suppressed.  Defau;t is \code{TRUE}, in contrast with most other methods.
##'     }
##'   }
##' }
##' \item{\code{env}}{
##'   Return a named character vector of environment variables that can be used to communicate with this vault server (\code{VAULT_ADDR}, \code{VAU:T_TOKEN}, etc).
##'   \cr\emph{Usage:}\code{env()}
##' }
##' \item{\code{export}}{
##'   Export the variables returned by the \code{$env()} method to the environment.  This makes them available to child processes.
##'   \cr\emph{Usage:}\code{export()}
##' }
##' \item{\code{clear_cached_token}}{
##'   Clear any session-cached token for this server.  This is intended for testing new authentication backends.
##'   \cr\emph{Usage:}\code{clear_cached_token()}
##' }
##' \item{\code{kill}}{
##'   Kill the server.
##'   \cr\emph{Usage:}\code{kill()}
##' }
##' }
