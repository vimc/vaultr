##' Interact with vault's token methods.  This includes support for
##' querying, creating and deleting tokens.  Tokens are fundamental to
##' the way that vault works, so there are a lot of methods here.  The
##' \href{https://www.vaultproject.io/docs/concepts/tokens.html}{vault
##' documentation has a page devoted to token concepts} and
##' \href{https://www.vaultproject.io/docs/commands/token/index.html}{another
##' with commands} that have names very similar to the names used
##' here.
##'
##' @section Token Accessors:
##'
##' Many of the methods use "token accessors" - whenever a token is
##' created, an "accessor" is created at the same time.  This is
##' another token that can be used to perform limited actions with the
##' token such as
##'
##' \itemize{
##' \item Look up a token's properties (not including the actual token ID)
##' \item Look up a token's capabilities on a path
##' \item Revoke the token
##' }
##'
##' However, accessors cannot be used to login, nor to retrieve the
##' actual token itself.
##'
##' @title Vault Tokens
##' @name vault_client_token
##' @examples
##'
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   # There are lots of token methods here:
##'   client$token
##'
##'   # To demonstrate, it will be useful to create a restricted
##'   # policy that can only read from the /secret path
##'   rules <- 'path "secret/*" {policy = "read"}'
##'   client$policy$write("read-secret", rules)
##'   client$write("/secret/path", list(key = "value"))
##'
##'   # Create a token that has this policy
##'   token <- client$auth$token$create(policies = "read-secret")
##'   alice <- vaultr::vault_client(addr = server$addr)
##'   alice$login(method = "token", token = token)
##'   alice$read("/secret/path")
##'
##'   client$token$lookup(token)
##'
##'   # We can query the capabilities of this token
##'   client$token$capabilities("secret/path", token)
##'
##'   # Tokens are not safe to pass around freely because they *are*
##'   # the ability to login, but the `token$create` command also
##'   # provides an accessor:
##'   accessor <- attr(token, "info")$accessor
##'
##'   # It is not possible to derive the token from the accessor, but
##'   # we can use the accessor to ask vault what it could do if it
##'   # did have the token (and do things like revoke the token)
##'   client$token$capabilities_accessor("secret/path", accessor)
##'
##'   client$token$revoke_accessor(accessor)
##'   try(client$token$capabilities_accessor("secret/path", accessor))
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_token <- R6::R6Class(
  "vault_client_token",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL
  ),

  public = list(
    ##' @description Create a `vault_client_token` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    initialize = function(api_client) {
      super$initialize("Interact and configure vault's token support")
      private$api_client <- api_client
    },

    ##' @description List token accessors, returning a character vector
    list = function() {
      dat <- private$api_client$LIST("/auth/token/accessors")
      list_to_character(dat$data$keys)
    },

    ##' @description Fetch the capabilities of a token on the given
    ##'   paths. The capabilities returned will be derived from the
    ##'   policies that are on the token, and from the policies to
    ##'   which the token is entitled to through the entity and
    ##'   entity's group memberships.
    ##'
    ##' @param path Vector of paths on which capabilities are being
    ##'   queried
    ##'
    ##' @param token Single token for which capabilities are being
    ##'   queried
    capabilities = function(path, token) {
      body <- list(paths = I(assert_character(path)),
                   token = assert_scalar_character(token))
      data <- private$api_client$POST("/sys/capabilities", body = body)
      lapply(data$data[path], list_to_character)
    },

    ##' @description As for the `capabilities` method, but for the
    ##'   client token used to make the request.
    ##'
    ##' @param path Vector of paths on which capabilities are being
    ##'   queried
    capabilities_self = function(path) {
      body <- list(paths = I(assert_character(path)))
      data <- private$api_client$POST("/sys/capabilities-self", body = body)
      lapply(data$data[path], list_to_character)
    },

    ##' @description As for the `capabilities` method, but using a
    ##'   token *accessor* rather than a token itself.
    ##'
    ##' @param path Vector of paths on which capabilities are being
    ##'   queried
    ##'
    ##' @param accessor Accessor of the token for which capabilities
    ##'   are being queried
    capabilities_accessor = function(path, accessor) {
      body <- list(paths = I(assert_character(path)),
                   accessor = assert_scalar_character(accessor))
      data <- private$api_client$POST("/sys/capabilities-accessor", body = body)
      lapply(data$data[path], list_to_character)
    },

    ##' @description
    ##'     Return the current client token
    client = function() {
      private$api_client$token
    },

    ##' @description Create a new token
    ##'
    ##' @param role_name The name of the token role
    ##'
    ##' @param id The ID of the client token. Can only be specified by
    ##'   a root token. Otherwise, the token ID is a randomly generated
    ##'   value
    ##'
    ##' @param policies A character vector of policies for the
    ##'   token. This must be a subset of the policies belonging to the
    ##'   token making the request, unless root. If not specified,
    ##'   defaults to all the policies of the calling token.
    ##'
    ##' @param meta A named list of strings as metadata to pass through
    ##'   to audit devices.
    ##'
    ##' @param orphan Logical, indicating if the token created should
    ##'   be an orphan (they will have no parent). As such, they will
    ##'   not be automatically revoked by the revocation of any other
    ##'   token.
    ##'
    ##' @param no_default_policy Logical, if `TRUE`, then the default
    ##'   policy will not be contained in this token's policy set.
    ##'
    ##' @param max_ttl Provides a maximum lifetime for any tokens
    ##'   issued against this role, including periodic tokens. Unlike
    ##'   direct token creation, where the value for an explicit max
    ##'   TTL is stored in the token, for roles this check will always
    ##'   use the current value set in the role. The main use of this
    ##'   is to provide a hard upper bound on periodic tokens, which
    ##'   otherwise can live forever as long as they are renewed. This
    ##'   is an integer number of seconds
    ##'
    ##' @param display_name The display name of the token
    ##'
    ##' @param num_uses Maximum number of uses that a token can have.
    ##'    This can be used to create a one-time-token or limited use
    ##'    token. The default, or the value of 0, has no limit to the
    ##'    number of uses.
    ##'
    ##' @param period If specified, the token will be periodic; it will
    ##'    have no maximum TTL (unless a `max_ttl` is also set) but
    ##'    every renewal will use the given period. Requires a
    ##'    root/sudo token to use.
    ##'
    ##' @param ttl The TTL period of the token, provided as "1h", where
    ##'   hour is the largest suffix. If not provided, the token is
    ##'   valid for the default lease TTL, or indefinitely if the root
    ##'   policy is used.
    ##'
    ##' @param wrap_ttl Indicates that the secret should be wrapped.
    ##'   This is discussed in [vault
    ##'   documentation](https://www.vaultproject.io/docs/concepts/response-wrapping.html).
    ##'   When this option is used, `vault` will take the response it
    ##'   would have sent to an HTTP client and instead insert it into
    ##'   the cubbyhole of a single-use token, returning that
    ##'   single-use token instead. Logically speaking, the response is
    ##'   wrapped by the token, and retrieving it requires an unwrap
    ##'   operation against this token (see the `$unwrap` method
    ##'   [vaultr::vault_client].  Must be specified as a valid
    ##'   duration (e.g., `1h`).
    create = function(role_name = NULL, id = NULL, policies = NULL,
                      meta = NULL, orphan = FALSE, no_default_policy = FALSE,
                      max_ttl = NULL, display_name = NULL,
                      num_uses = 0L, period = NULL, ttl = NULL,
                      wrap_ttl = NULL) {
      body <- list(
        role_name = role_name %&&% assert_scalar_character(role_name),
        policies = policies %&&% I(assert_character(policies)),
        meta = meta,
        no_default_policy = assert_scalar_logical(no_default_policy),
        explicit_max_ttl = max_ttl %&&% assert_scalar_integer(max_ttl),
        display_name = display_name %&&% assert_scalar_character(display_name),
        num_uses = num_uses %&&% assert_scalar_integer(num_uses),
        ttl = ttl %&&% assert_is_duration(ttl),
        ## root only:
        id = role_name %&&% assert_scalar_character(id),
        period = period %&&% assert_is_duration(period),
        no_parent = assert_scalar_logical(orphan))
      body <- drop_null(body)
      res <- private$api_client$POST("/auth/token/create", body = body,
                                     wrap_ttl = wrap_ttl)
      if (is.null(wrap_ttl)) {
        info <- res$auth
        info$policies <- list_to_character(info$policies)
        token <- info$client_token
      } else {
        info <- res$wrap_info
        token <- info$token
      }
      attr(token, "info") <- info
      token
    },

    ##' @description Returns information about the client token
    ##'
    ##' @param token The token to lookup
    lookup = function(token = NULL) {
      body <- list(token = assert_scalar_character(token))
      res <- private$api_client$POST("/auth/token/lookup", body = body)
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

    ##' @description Returns information about the current client token
    ##'   (as if calling `$lookup` with the token the client is using.
    lookup_self = function() {
      res <- private$api_client$GET("/auth/token/lookup-self")
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

    ##' @description Returns information about the client token from
    ##'   the accessor.
    ##'
    ##' @param accessor The token accessor to lookup
    lookup_accessor = function(accessor) {
      body <- list(accessor = assert_scalar_character(accessor))
      res <- private$api_client$POST("/auth/token/lookup-accessor", body = body)
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

    ##' @description Renews a lease associated with a token. This is
    ##'   used to prevent the expiration of a token, and the automatic
    ##'   revocation of it. Token renewal is possible only if there is
    ##'   a lease associated with it.
    ##'
    ##' @param token The token to renew
    ##'
    ##' @param increment An optional requested lease increment can be
    ##'   provided. This increment may be ignored.  If given, it should
    ##'   be a duration (e.g., `1h`).
    renew = function(token, increment = NULL) {
      body <- list(token = assert_scalar_character(token))
      if (!is.null(increment)) {
        body$increment <- assert_is_duration(increment)
      }
      res <- private$api_client$POST("/auth/token/renew", body = body)
      info <- res$auth
      info$policies <- list_to_character(info$policies)
      info
    },

    ##' @description Renews a lease associated with the calling
    ##'   token. This is used to prevent the expiration of a token, and
    ##'   the automatic revocation of it. Token renewal is possible
    ##'   only if there is a lease associated with it.  This is
    ##'   equivalent to calling `$renew()` with the client token.
    ##'
    ##' @param increment An optional requested lease increment can be
    ##'   provided. This increment may be ignored.  If given, it should
    ##'   be a duration (e.g., `1h`).
    renew_self = function(increment = NULL) {
      body <- list(
        increment = increment %&&% assert_is_duration(increment))
      res <- private$api_client$POST("/auth/token/renew-self",
                                     body = drop_null(body))
      info <- res$auth
      info$policies <- list_to_character(info$policies)
      info
    },

    ##' @description Revokes a token and all child tokens. When the
    ##'   token is revoked, all dynamic secrets generated with it are
    ##'   also revoked.
    ##'
    ##' @param token The token to revoke
    revoke = function(token) {
      body <- list(token = assert_scalar_character(token))
      private$api_client$POST("/auth/token/revoke", body = body)
      invisible(NULL)
    },

    ##' @description Revokes the token used to call it and all child
    ##'   tokens. When the token is revoked, all dynamic secrets
    ##'   generated with it are also revoked.  This is equivalent to
    ##'   calling `$revoke()` with the client token.
    revoke_self = function() {
      private$api_client$POST("/auth/token/revoke-self")
      invisible(NULL)
    },

    ##' @description Revoke the token associated with the accessor and
    ##'   all the child tokens. This is meant for purposes where there
    ##'   is no access to token ID but there is need to revoke a token
    ##'   and its children.
    ##'
    ##' @param accessor Accessor of the token to revoke.
    revoke_accessor = function(accessor) {
      body <- list(accessor = assert_scalar_character(accessor))
      private$api_client$POST("/auth/token/revoke-accessor", body = body)
      invisible(NULL)
    },

    ##' @description Revokes a token but not its child tokens. When the
    ##'   token is revoked, all secrets generated with it are also
    ##'   revoked. All child tokens are orphaned, but can be revoked
    ##'   subsequently using /auth/token/revoke/. This is a
    ##'   root-protected method.
    ##'
    ##' @param token The token to revoke
    revoke_and_orphan = function(token) {
      body <- list(token = assert_scalar_character(token))
      private$api_client$POST("/auth/token/revoke-orphan", body = body)
      invisible(NULL)
    },

    ##' @description Fetches the named role configuration.
    ##'
    ##' @param role_name The name of the token role.
    role_read = function(role_name) {
      path <- sprintf("/auth/token/roles/%s",
                      assert_scalar_character(role_name))
      data <- private$api_client$GET(path)$data
      data$allowed_policies <- list_to_character(data$allowed_policies)
      data$disallowed_policies <- list_to_character(data$disallowed_policies)
      data
    },

    ##' @description List available token roles.
    role_list = function() {
      dat <- tryCatch(private$api_client$LIST("/auth/token/roles"),
                      vault_invalid_path = function(e) NULL)
      list_to_character(dat$data$keys)
    },

    ##' @description Creates (or replaces) the named role. Roles
    ##'   enforce specific behaviour when creating tokens that allow
    ##'   token functionality that is otherwise not available or would
    ##'   require sudo/root privileges to access. Role parameters, when
    ##'   set, override any provided options to the create
    ##'   endpoints. The role name is also included in the token path,
    ##'   allowing all tokens created against a role to be revoked
    ##'   using the `/sys/leases/revoke-prefix` endpoint.
    ##'
    ##' @param role_name Name for the role - this will be used later to
    ##'   refer to the role (e.g., in `$create` and other `$role_*`
    ##'   methods.
    ##'
    ##' @param allowed_policies Character vector of policies allowed
    ##'   for this role.  If set, tokens can be created with any subset
    ##'   of the policies in this list, rather than the normal
    ##'   semantics of tokens being a subset of the calling token's
    ##'   policies. The parameter is a comma-delimited string of policy
    ##'   names. If at creation time `no_default_policy` is not set and
    ##'   "default" is not contained in disallowed_policies, the
    ##'   "default" policy will be added to the created token
    ##'   automatically.
    ##'
    ##' @param disallowed_policies Character vector of policies
    ##'   forbidden for this role.  If set, successful token creation
    ##'   via this role will require that no policies in the given list
    ##'   are requested. Adding "default" to this list will prevent
    ##'   "default" from being added automatically to created tokens.
    ##'
    ##' @param orphan If `TRUE`, then tokens created against this
    ##'   policy will be orphan tokens (they will have no parent). As
    ##'   such, they will not be automatically revoked by the
    ##'   revocation of any other token.
    ##'
    ##' @param period A duration (e.g., `1h`).  If specified, the token
    ##'   will be periodic; it will have no maximum TTL (unless an
    ##'   "explicit-max-ttl" is also set) but every renewal will use
    ##'   the given period. Requires a root/sudo token to use.
    ##'
    ##' @param renewable Set to `FALSE` to disable the ability of the
    ##'   token to be renewed past its initial TTL. The default value
    ##'   of `TRUE` will allow the token to be renewable up to the
    ##'   system/mount maximum TTL.
    ##'
    ##' @param explicit_max_ttl An integer number of seconds.  Provides
    ##'   a maximum lifetime for any tokens issued against this role,
    ##'   including periodic tokens. Unlike direct token creation,
    ##'   where the value for an explicit max TTL is stored in the
    ##'   token, for roles this check will always use the current value
    ##'   set in the role. The main use of this is to provide a hard
    ##'   upper bound on periodic tokens, which otherwise can live
    ##'   forever as long as they are renewed. This is an integer
    ##'   number of seconds.
    ##'
    ##' @param path_suffix A string.  If set, tokens created against
    ##'   this role will have the given suffix as part of their path in
    ##'   addition to the role name. This can be useful in certain
    ##'   scenarios, such as keeping the same role name in the future
    ##'   but revoking all tokens created against it before some point
    ##'   in time. The suffix can be changed, allowing new callers to
    ##'   have the new suffix as part of their path, and then tokens
    ##'   with the old suffix can be revoked via
    ##'   `/sys/leases/revoke-prefix`.
    ##'
    ##' @param bound_cidrs Character vector of CIDRS.  If set,
    ##'   restricts usage of the generated token to client IPs falling
    ##'   within the range of the specified CIDR(s). Unlike most other
    ##'   role parameters, this is not reevaluated from the current
    ##'   role value at each usage; it is set on the token itself. Root
    ##'   tokens with no TTL will not be bound by these CIDRs; root
    ##'   tokens with TTLs will be bound by these CIDRs.
    ##'
    ##' @param token_type Specifies the type of tokens that should be
    ##'   returned by the role. If either service or batch is
    ##'   specified, that kind of token will always be returned. If
    ##'   `default-service`, then `service` tokens will be returned
    ##'   unless the client requests a batch type token at token
    ##'   creation time. If `default-batch`, then `batch` tokens will
    ##'   be returned unless the client requests a service type token
    ##'   at token creation time.
    role_write = function(role_name, allowed_policies = NULL,
                          disallowed_policies = NULL, orphan = NULL,
                          period = NULL, renewable = NULL,
                          explicit_max_ttl = NULL, path_suffix = NULL,
                          bound_cidrs = NULL, token_type = NULL) {
      path <- sprintf("/auth/token/roles/%s",
                      assert_scalar_character(role_name))
      body <- list(
        allowed_policies =
          allowed_policies %&&% assert_character(allowed_policies),
        disallowed_policies =
          disallowed_policies %&&% assert_character(disallowed_policies),
        orphan = orphan %&&% assert_scalar_logical(orphan),
        period = period %&&% assert_duration(period),
        renewable = orphan %&&% assert_scalar_logical(orphan),
        explicit_max_ttl =
          explicit_max_ttl %&&% assert_scalar_integer(explicit_max_ttl),
        path_suffix = path_suffix %&&% assert_scalar_character(path_suffix),
        bound_cidrs = bound_cidrs %&&% assert_character(bound_cidrs),
        token_type = token_type %&&% assert_scalar_character(token_type))
      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Delete a named token role
    ##'
    ##' @param role_name The name of the role to delete
    role_delete = function(role_name) {
      path <- sprintf("/auth/token/roles/%s",
                      assert_scalar_character(role_name))
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    ##' @description Performs some maintenance tasks to clean up
    ##'   invalid entries that may remain in the token
    ##'   store. Generally, running this is not needed unless upgrade
    ##'   notes or support personnel suggest it. This may perform a lot
    ##'   of I/O to the storage method so should be used sparingly.
    tidy = function() {
      private$api_client$POST("/auth/token/tidy")
      invisible(NULL)
    },

    ## Not really a *login* as such, but this is where we centralise
    ## the variable lookup information:

    ##' @description Unlike other auth backend `login` methods, this
    ##'   does not actually log in to the vault.  Instead it verifies
    ##'   that a token can be used to communicate with the vault.
    ##'
    ##' @param token The token to test
    ##'
    ##' @param quiet Logical scalar, set to `TRUE` to suppress
    ##'   informational messages.
    login = function(token = NULL, quiet = FALSE) {
      token <- vault_auth_vault_token(token)
      res <- private$api_client$verify_token(token, quiet = quiet)
      if (!res$success) {
        stop(paste("Token login failed with error:", res$error$message),
             call. = FALSE)
      }
      res$token
    }
  ))


vault_auth_vault_token <- function(token) {
  if (is.null(token)) {
    token <- Sys_getenv("VAULT_TOKEN", NULL)
  }
  if (is.null(token)) {
    stop("Vault token was not found: perhaps set 'VAULT_TOKEN'",
         call. = FALSE)
  }
  assert_scalar_character(token)
  token
}
