##' @section Methods:
##'
##' \describe{
##' \item{\code{list}}{
##'   List active audit devices.  Returns a \code{data.frame} of names, paths and descriptions of active audit devices.
##'   \cr\emph{Usage:}\preformatted{list()}
##' }
##' \item{\code{enable}}{
##'   This endpoint enables a new audit device at the supplied path.
##'   \cr\emph{Usage:}\preformatted{enable(type, description = NULL, options = NULL, path = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{type}:   Name of the audit device to enable
##'     }
##'
##'     \item{\code{description}:   Human readable description for this audit device
##'     }
##'
##'     \item{\code{options}:   Options to configure the device with.  These vary by device. This must be a named list of strings.
##'     }
##'
##'     \item{\code{path}:   Path to mount the audit device.  By default, \code{type} is used as the path.
##'     }
##'   }
##' }
##' \item{\code{disable}}{
##'   Disable an audit device
##'   \cr\emph{Usage:}\preformatted{disable(path)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   Path of the audit device to remove
##'     }
##'   }
##' }
##' \item{\code{hash}}{
##'   The \code{hash} method is used to calculate the hash of the data used by an audit device's hash function and salt. This can be used to search audit logs for a hashed value when the original value is known.
##'   \cr\emph{Usage:}\preformatted{hash(input, device)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{input}:   The input string to hash
##'     }
##'
##'     \item{\code{device}:   The path of the audit device
##'     }
##'   }
##' }
##' }
