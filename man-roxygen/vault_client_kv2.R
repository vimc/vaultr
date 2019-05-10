##' @section Methods:
##'
##' \describe{
##' \item{\code{config}}{
##'   Fetch the configuration for this \code{kv2} store.  Returns a named list of values, the contents of which will depend on the vault version.
##'   \cr\emph{Usage:}\preformatted{config(mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{custom_mount}}{
##'   Set up a \code{vault_client_kv2} object at a custom mount.  For example, suppose you mounted another copy of the \code{kv2} secret backend at \code{/secret2} you might use \code{kv <- vault$secrets$kv2$custom_mount("/secret2")} - this pattern is repeated for other secret and authentication backends.
##'   \cr\emph{Usage:}\preformatted{custom_mount(mount)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{mount}:   String, indicating the path that the engine is mounted at.
##'     }
##'   }
##' }
##' \item{\code{delete}}{
##'   Delete a secret from the vault.  This marks the version as deleted and will stop it from being returned from reads, but the underlying data will not be removed. A delete can be undone using the undelete method.
##'   \cr\emph{Usage:}\preformatted{delete(path, version = NULL, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path to delete
##'     }
##'
##'     \item{\code{version}:   Optional version to delete.  If \code{NULL} (the default) then the latest version of the secret is deleted.  Otherwise, \code{version} can be a vector of integer versions to delete.
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{destroy}}{
##'   Delete a secret entirely.  Unlike \code{delete} this operation is irreversible and is more like the \code{delete} operation on \code{\link{vault_client_kv1}} stores.
##'   \cr\emph{Usage:}\preformatted{destroy(path, version, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path to delete
##'     }
##'
##'     \item{\code{version}:   Version numbers to delete, as a vector of integers (this is required)
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{get}}{
##'   Read a secret from the vault
##'   \cr\emph{Usage:}\preformatted{get(path, version = NULL, field = NULL, metadata = FALSE,
##'       mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path of the secret to read
##'     }
##'
##'     \item{\code{version}:   Optional version of the secret to read.  If \code{NULL} (the default) then the most recent version is read.  Otherwise this must be a scalar integer.
##'     }
##'
##'     \item{\code{field}:   Optional field to read from the secret.  Each secret is stored as a key/value set (represented in R as a named list) and this is equivalent to using \code{[[field]]} on the return value. The default, \code{NULL}, returns the full set of values.
##'     }
##'
##'     \item{\code{metadata}:   Logical, indicating if we should return metadata for this secret (lease information etc) as an attribute along with hte values itself.  Ignored if \code{field} is specified.
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{list}}{
##'   List data in the vault at a give path.  This can be used to list keys, etc (e.g., at \code{/secret}).
##'   \cr\emph{Usage:}\preformatted{list(path, full_names = FALSE, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The path to list
##'     }
##'
##'     \item{\code{full_names}:   Logical, indicating if full paths (relative to the vault root) should be returned.
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##'
##'   \emph{Value}:
##'   A character vector (of zero length if no keys are found).  Paths that are "directories" (i.e., that contain keys and could themselves be listed) will be returned with a trailing forward slash, e.g. \code{path/}
##' }
##' \item{\code{metadata_get}}{
##'   Read secret metadata and versions at the specified path
##'   \cr\emph{Usage:}\preformatted{metadata_get(path, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path of secret to read metadata for
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{metadata_put}}{
##'   Update metadata for a secret.  This is allowed even if a secret does not yet exist, though this requires the \code{create} vault permission at this path.
##'   \cr\emph{Usage:}\preformatted{metadata_put(path, cas_required = NULL, max_versions = NULL, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path of secret to update metadata for
##'     }
##'
##'     \item{\code{cas_required}:   Logical, indicating that if If true the key will require the cas parameter to be set on all write requests (see \code{put}). If \code{FALSE}, the backend’s configuration will be used.
##'     }
##'
##'     \item{\code{max_versions}:   Integer, indicating the maximum number of versions to keep per key.  If not set, the backend’s configured max version is used. Once a key has more than the configured allowed versions the oldest version will be permanently deleted.
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{metadata_delete}}{
##'   This method permanently deletes the key metadata and all version data for the specified key. All version history will be removed.
##'   \cr\emph{Usage:}\preformatted{metadata_delete(path, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path to delete
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{put}}{
##'   Create or update a secret in this store.
##'   \cr\emph{Usage:}\preformatted{put(path, data, cas = NULL, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path for the secret to write, such as \code{/secret/mysecret}
##'     }
##'
##'     \item{\code{data}:   A named list of values to write into the vault at this path.
##'     }
##'
##'     \item{\code{cas}:   Integer, indicating the "cas" value to use a "Check-And-Set" operation. If not set the write will be allowed. If set to 0 a write will only be allowed if the key doesn’t exist. If the index is non-zero the write will only be allowed if the key’s current version matches the version specified in the cas parameter.
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' \item{\code{undelete}}{
##'   Undeletes the data for the provided version and path in the key-value store. This restores the data, allowing it to be returned on get requests.  This works with data deleted with \code{$delete} but not with \code{$destroy}.
##'   \cr\emph{Usage:}\preformatted{undelete(path, version, mount = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The path to undelete
##'     }
##'
##'     \item{\code{version}:   Integer vector of versions to undelete
##'     }
##'
##'     \item{\code{mount}:   Custom mount path to use for this store (see \code{Details}.
##'     }
##'   }
##' }
##' }
