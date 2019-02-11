##' @section Methods:
##' \cr\describe{
##' \item{\code{custom_mount}}{
##'   Set up a \code{vault_client_auth_github} object at a custom mount. For example, suppose you mounted the \code{github} authentication backend at \code{/github-myorg} you might use \code{gh <- vault$auth$github2$custom_mount("/github-myorg")} - this pattern is repeated for other secret and authentication backends.
##'   \cr\emph{Usage:}\code{custom_mount(mount)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{mount}:   String, indicating the path that the engine is mounted at.
##'     }
##'   }
##' }
##' \item{\code{configure}}{
##'   Configures the connection parameters for GitHub-based authentication.
##'   \cr\emph{Usage:}\code{configure(organization, base_url = NULL, ttl = NULL, max_ttl = NULL)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{organization}:   The organization users must be part of (note American spelling).
##'     }
##'
##'     \item{\code{base_url}:   The API endpoint to use. Useful if you are running GitHub Enterprise or an API-compatible authentication server.
##'     }
##'
##'     \item{\code{ttl}:   Duration after which authentication will be expired
##'     }
##'
##'     \item{\code{max_ttl}:   Maximum duration after which authentication will be expired
##'     }
##'   }
##' }
##' \item{\code{configuration}}{
##'   Reads the connection parameters for GitHub-based authentication.
##'   \cr\emph{Usage:}\code{configuration()}
##' }
##' \item{\code{write}}{
##'   Write a mapping between a GitHub team or user and a set of vault policies.
##'   \cr\emph{Usage:}\code{write(team_name, policy, user = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{team_name}:   String, with the GitHub team name
##'     }
##'
##'     \item{\code{policy}:   A character vector of vault policies that this user or team will have for vault access if they match this team or user.
##'     }
##'
##'     \item{\code{user}:   Scalar logical - if \code{TRUE}, then \code{team_name} is interpreted as a \emph{user} instead.
##'     }
##'   }
##' }
##' \item{\code{read}}{
##'   Write a mapping between a GitHub team or user and a set of vault policies.
##'   \cr\emph{Usage:}\code{read(team_name, user = FALSE)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{team_name}:   String, with the GitHub team name
##'     }
##'
##'     \item{\code{user}:   Scalar logical - if \code{TRUE}, then \code{team_name} is interpreted as a \emph{user} instead.
##'     }
##'   }
##' }
##' \item{\code{login}}{
##'   Log into the vault using GitHub authentication.  Normally you would not call this directly but instead use \code{$login} with \code{method = "github"} and proving the \code{token} argument. This function returns a vault token but does not set it as the client token.
##'   \cr\emph{Usage:}\code{login(token = NULL)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{token}:   A GitHub token to authenticate with.
##'     }
##'   }
##' }
##' }
