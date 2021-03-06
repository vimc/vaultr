##' @section Methods:
##'
##' \describe{
##' \item{\code{read}}{
##'   Read a value from the vault.  This can be used to read any value that you have permission to read in this store.
##'   \cr\emph{Usage:}\preformatted{read(path, field = NULL, metadata = FALSE)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path for the secret to read, such as \code{/secret/mysecret}
##'     }
##'
##'     \item{\code{field}:   Optional field to read from the secret.  Each secret is stored as a key/value set (represented in R as a named list) and this is equivalent to using \code{[[field]]} on the return value. The default, \code{NULL}, returns the full set of values.
##'     }
##'
##'     \item{\code{metadata}:   Logical, indicating if we should return metadata for this secret (lease information etc) as an attribute along with the values itself.  Ignored if \code{field} is specified.
##'     }
##'   }
##' }
##' \item{\code{write}}{
##'   Write data into the vault.  This can be used to write any value that you have permission to write in this store.
##'   \cr\emph{Usage:}\preformatted{write(path, data)}
##'
##'   \emph{Arguments:}
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
##'   \cr\emph{Usage:}\preformatted{list(path, full_names = FALSE)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The path to list
##'     }
##'
##'     \item{\code{full_names}:   Logical, indicating if full paths (relative to the vault root) should be returned.
##'     }
##'   }
##'
##'   \emph{Value}:
##'   A character vector (of zero length if no keys are found).  Paths that are "directories" (i.e., that contain keys and could themselves be listed) will be returned with a trailing forward slash, e.g. \code{path/}
##' }
##' \item{\code{delete}}{
##'   Delete a value from the vault
##'   \cr\emph{Usage:}\preformatted{delete(path)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The path to delete
##'     }
##'   }
##' }
##' \item{\code{custom_mount}}{
##'   Set up a \code{vault_client_kv1} object at a custom mount.  For example, suppose you mounted another copy of the \code{kv1} secret backend at \code{/secret2} you might use \code{kv <- vault$secrets$kv1$custom_mount("/secret2")} - this pattern is repeated for other secret and authentication backends.
##'   \cr\emph{Usage:}\preformatted{custom_mount(mount)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{mount}:   String, indicating the path that the engine is mounted at.
##'     }
##'   }
##' }
##' }
