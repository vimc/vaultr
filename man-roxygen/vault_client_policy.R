##' @section Methods:
##' \cr\describe{
##' \item{\code{delete}}{
##'   This endpoint deletes the policy with the given name. This will immediately affect all users associated with this policy.
##'   \cr\emph{Usage:}\code{delete(name)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{name}:   Specifies the name of the policy to delete.
##'     }
##'   }
##' }
##' \item{\code{list}}{
##'   Lists all configured policies.
##'   \cr\emph{Usage:}\code{list()}
##' }
##' \item{\code{read}}{
##'   Retrieve the policy body for the named policy
##'   \cr\emph{Usage:}\code{read(name)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{name}:   Specifies the name of the policy to retrieve
##'     }
##'   }
##' }
##' \item{\code{write}}{
##'   Create or update a policy.  Once a policy is updated, it takes effect immediately to all associated users.
##'   \cr\emph{Usage:}\code{write(name, rules)}
##'   \cr\emph{Arguments:}
##'   \itemize{
##'     \item{\code{name}:   Name of the policy to update
##'     }
##'
##'     \item{\code{rules}:   Specifies the policy document.  This is a string in \href{https://learn.hashicorp.com/vault/identity-access-management/iam-policies}{HashiCorp configuration language}.  At present this must be read in as a single string (not a character vector of strings); future versions of vaultr may allow more flexible speficdication such as \code{@filename}.
##'     }
##'   }
##' }
##' }
