##' @section Methods:
##'
##' \describe{
##' \item{\code{custom_mount}}{
##'   Set up a \code{vault_client_auth_userpass} object at a custom mount. For example, suppose you mounted the \code{userpass} authentication backend at \code{/userpass2} you might use \code{up <- vault$auth$userpass2$custom_mount("/userpass2")} - this pattern is repeated for other secret and authentication backends.
##'
##'   \emph{Usage:}\code{custom_mount(mount)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{mount}:   String, indicating the path that the engine is mounted at.
##'     }
##'   }
##' }
##' \item{\code{write}}{
##'   Create or update a user.
##'
##'   \emph{Usage:}\code{write(username, password = NULL, policy = NULL, ttl = NULL,
##'       max_ttl = NULL, bound_cidrs = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username for the user
##'     }
##'
##'     \item{\code{password}:   Password for the user (required when creating a user only)
##'     }
##'
##'     \item{\code{policy}:   Character vector of policies for the user
##'     }
##'
##'     \item{\code{ttl}:   The lease duration which decides login expiration
##'     }
##'
##'     \item{\code{max_ttl}:   Maximum duration after which login should expire
##'     }
##'
##'     \item{\code{bound_cidrs}:   Character vector of CIDRs.  If set, restricts usage of the login and token to client IPs falling within the range of the specified CIDR(s).
##'     }
##'   }
##' }
##' \item{\code{read}}{
##'   Reads the properties of an existing username.
##'
##'   \emph{Usage:}\code{read(username)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username to read
##'     }
##'   }
##' }
##' \item{\code{delete}}{
##'   Delete a user
##'
##'   \emph{Usage:}\code{delete(username)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username to delete
##'     }
##'   }
##' }
##' \item{\code{update_password}}{
##'   Update password for a user
##'
##'   \emph{Usage:}\code{update_password(username, password)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username for the user to update
##'     }
##'
##'     \item{\code{password}:   New password for the user
##'     }
##'   }
##' }
##' \item{\code{update_policies}}{
##'   Update vault policies for a user
##'
##'   \emph{Usage:}\code{update_policies(username, policy)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username for the user to update
##'     }
##'
##'     \item{\code{policy}:   Character vector of policies for this user
##'     }
##'   }
##' }
##' \item{\code{list}}{
##'   List users known to vault
##'
##'   \emph{Usage:}\code{list()}
##' }
##' \item{\code{login}}{
##'   Log into the vault using username/password authentication. Normally you would not call this directly but instead use \code{$login} with \code{method = "userpass"} and proving the \code{username} argument and optionally the \code{password} argument.  This function returns a vault token but does not set it as the client token.
##'
##'   \emph{Usage:}\code{login(username, password = NULL)}
##'
##'   \emph{Arguments:}
##'   \itemize{
##'     \item{\code{username}:   Username to authenticate with
##'     }
##'
##'     \item{\code{password}:   Password to authenticate with. If omitted or \code{NULL} and the session is interactive, the password will be prompted for.
##'     }
##'   }
##' }
##' }
