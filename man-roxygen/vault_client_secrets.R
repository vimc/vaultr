##' @section Methods:
##'
##' \describe{
##' \item{\code{enable}}{
##'   Enable a secret backend in the vault server
##'   \cr\emph{Usage:}\preformatted{enable(type, path = type, description = NULL, version = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{type}:   The type of secret backend (e.g., \code{transit}, \code{kv}).
##'     }
##'
##'     \item{\code{path}:   Specifies the path in which to enable the auth method. Defaults to be the same as \code{type}.
##'     }
##'
##'     \item{\code{description}:   Human-friendly description of the backend; will be returned by \code{$list()}
##'     }
##'
##'     \item{\code{version}:   Used only for the \code{kv} backend, where an integer is used to select between \code{\link{vault_client_kv1}} and \code{\link{vault_client_kv2}} engines.
##'     }
##'   }
##' }
##' \item{\code{disable}}{
##'   Disable a previously-enabled secret engine
##'   \cr\emph{Usage:}\preformatted{disable(path)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path of the secret engine
##'     }
##'   }
##' }
##' \item{\code{list}}{
##'   List enabled secret engines
##'   \cr\emph{Usage:}\preformatted{list(detailed = FALSE)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{detailed}:   Logical, indicating if detailed output is wanted.
##'     }
##'   }
##' }
##' \item{\code{move}}{
##'   Move the path that a secret engine is mounted at
##'   \cr\emph{Usage:}\preformatted{move(from, to)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{from}:   Original path
##'     }
##'
##'     \item{\code{to}:   New path
##'     }
##'   }
##' }
##' }
