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
##' \item{\code{list}}{
##'   List data in the vault at a give path.  This can be used to list keys, etc (e.g., at \code{/secret}).
##'   \cr\emph{Usage:}\code{list(path, full_names = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The path to list
##'     }
##'
##'     \item{\code{full_names}:   Logical, indicating if full paths (relative to the vault root) should be returned.
##'     }
##'   }
##'   \cr\emph{Value}:
##'   A character vector (of zero length if no keys are found).  Paths that are "directories" (i.e., that contain keys and could themselves be listed) will be returned with a trailing forward slash, e.g. \code{path/}
##' }
##' \item{\code{login}}{
##'   Login to the vault.  This method is more complicated than most.
##'   \cr\emph{Usage:}\code{login(..., method = "token", mount = NULL, renew = FALSE,
##'       quiet = FALSE, token_only = FALSE, use_cache = TRUE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'
##'   }
##' }
##' \item{\code{status}}{
##'   Return the status of the vault server, including whether it is sealed or not, and the valut server version.
##'   \cr\emph{Usage:}\code{status()}
##' }
##' }
