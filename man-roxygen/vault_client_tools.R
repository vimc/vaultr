##' @section Methods:
##' \cr\describe{
##' \item{\code{random}}{
##'   Generates high-quality random bytes of the specified length.  This is totally independent of R's random number stream and provides random numbers suitable for cryptographic purposes.
##'   \cr\emph{Usage:}\code{random(bytes = 32, format = "hex")}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{bytes}:   Number of bytes to generate (as an integer)
##'     }
##'
##'     \item{\code{format}:   The output format to produce; must be one of \code{hex} (a single hex string such as \code{d1189e2f83b72ab6}), \code{base64} (a single base64 encoded string such as \code{8TDJekY0mYs=}) or \code{raw} (a raw vector of length \code{bytes}).
##'     }
##'   }
##' }
##' \item{\code{hash}}{
##'   Generates a cryptographic hash of given data using the specified algorithm.
##'   \cr\emph{Usage:}\code{hash(data, algorithm = NULL, format = "hex")}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{data}:   A raw vector of data to hash.  To generate a raw vector from an R object, one option is to use \code{unserialize(x, NULL)} but be aware that version information may be included. Alternatively, for a string, one might use \code{charToRaw}.
##'     }
##'
##'     \item{\code{algorithm}:   A string indicating the hash algorithm to use.  The exact set of supported algorithms may depend by vault server version, but as of version 1.0.0 vault supports \code{sha2-224}, \code{sha2-256}, \code{sha2-384} and \code{sha2-512}.  The default is \code{sha2-256}.
##'     }
##'
##'     \item{\code{format}:   The format of the output - must be one of \code{hex} or \code{base64}.
##'     }
##'   }
##' }
##' }
