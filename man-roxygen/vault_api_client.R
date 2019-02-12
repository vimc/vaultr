##' @section Methods:
##' \cr\describe{
##' \item{\code{is_authenticated}}{
##'   Test if the vault client currently holds a vault token.  This method does not verify the token - only test that is present.
##'   \cr\emph{Usage:}\code{is_authenticated()}
##' }
##' \item{\code{set_token}}{
##'   Set a token within the client
##'   \cr\emph{Usage:}\code{set_token(token, verify = FALSE, quiet = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{token}:   String, with the new vault client token
##'     }
##'
##'     \item{\code{verify}:   Logical, indicating if we should test that the token is valid. If \code{TRUE}, then we use \code{$verify_token()} to test the token before setting it and if it is not valid an error will be thrown and the token not set.
##'     }
##'
##'     \item{\code{quiet}:   Logical, if \code{TRUE}, then informational messages will be suppressed.
##'     }
##'   }
##' }
##' \item{\code{verify_token}}{
##'   Test that a token is valid with the vault.  This will call vault's \code{/sys/capabilities-self} endpoint with the token provided and check the \code{/sys} path.
##'   \cr\emph{Usage:}\code{verify_token(token, quiet = TRUE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{token}:   String, with the vault client token to test
##'     }
##'
##'     \item{\code{quiet}:   Logical, if \code{TRUE}, then informational messages will be suppressed.
##'     }
##'   }
##' }
##' \item{\code{server_version}}{
##'   Retrieve the vault server version.  This is by default cached within the client for a session.  Will return an R \code{numeric_version} object.
##'   \cr\emph{Usage:}\code{server_version(refresh = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{refresh}:   Logical, indicating if the server version information should be refreshed even if known.
##'     }
##'   }
##' }
##' \item{\code{GET}}{
##'   Send a \code{GET} request to the vault server
##'   \cr\emph{Usage:}\code{GET(path, ...)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The server path to use.  This is the "interesting" part of the path only, with the server base url and api version information added.
##'     }
##'
##'     \item{\code{...}:   Additional \code{httr}-compatible options.  These will be named parameters or \code{httr} "request" objects.
##'     }
##'   }
##' }
##' \item{\code{LIST}}{
##'   Send a \code{LIST} request to the vault server
##'   \cr\emph{Usage:}\code{LIST(path, ...)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The server path to use.  This is the "interesting" part of the path only, with the server base url and api version information added.
##'     }
##'
##'     \item{\code{...}:   Additional \code{httr}-compatible options.  These will be named parameters or \code{httr} "request" objects.
##'     }
##'   }
##' }
##' \item{\code{POST}}{
##'   Send a \code{POST} request to the vault server
##'   \cr\emph{Usage:}\code{POST(path, ...)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The server path to use.  This is the "interesting" part of the path only, with the server base url and api version information added.
##'     }
##'
##'     \item{\code{...}:   Additional \code{httr}-compatible options.  These will be named parameters or \code{httr} "request" objects.
##'     }
##'   }
##' }
##' \item{\code{PUT}}{
##'   Send a \code{PUT} request to the vault server
##'   \cr\emph{Usage:}\code{PUT(path, ...)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The server path to use.  This is the "interesting" part of the path only, with the server base url and api version information added.
##'     }
##'
##'     \item{\code{...}:   Additional \code{httr}-compatible options.  These will be named parameters or \code{httr} "request" objects.
##'     }
##'   }
##' }
##' \item{\code{DELETE}}{
##'   Send a \code{DELETE} request to the vault server
##'   \cr\emph{Usage:}\code{DELETE(path, ...)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{path}:   The server path to use.  This is the "interesting" part of the path only, with the server base url and api version information added.
##'     }
##'
##'     \item{\code{...}:   Additional \code{httr}-compatible options.  These will be named parameters or \code{httr} "request" objects.
##'     }
##'   }
##' }
##' }
