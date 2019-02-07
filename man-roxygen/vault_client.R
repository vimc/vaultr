##' @section Methods:
##' \cr\describe{
##' \item{\code{api}}{
##'   Returns an api client object that can be used to directly interact with the vault server.
##'   \cr\emph{Usage:}\code{api()}
##' }
##' \item{\code{read}}{
##'   Read a value from the vault.  This can be used to read any value that you have permission to read, and can also be used as an interface to a version 1 key-value store (see \code{\link{vault_client_kv1}}.  Similar to the vault CLI command \code{vault read}.
##'   \cr\emph{Usage:}\code{read(path, field = NULL, metadata = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path for the secret to read, such as \code{/secret/mysecret}
##'     }
##'
##'     \item{\code{field}:   Optional field to read from the secret.  Each secret is stored as a key/value set (represented in R as a named list) and this is equivalent to using \code{[[field]]} on the return value. The default, \code{NULL}, returns the full set of values.
##'     }
##'
##'     \item{\code{metadata}:   Logical, indicating if we should return metadata for this secret (lease information etc) as an attribute along with hte values itself.  Ignored if \code{field} is specified.
##'     }
##'   }
##' }
##' \item{\code{write}}{
##'   Write data into the vault.  This can be used to write any value that you have permission to write, and can also be used as an interface to a version 1 key-value store (see \code{\link{vaule_client_kv1}}.  Similar to the vault CLI command \code{vault write}.
##'   \cr\emph{Usage:}\code{write(path, data)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path for the secret to write, such as \code{/secret/mysecret}
##'     }
##'
##'     \item{\code{data}:   A named list of values to write into the vault at this path. This \emph{replaces} any existing values.
##'     }
##'   }
##' }
##' }
