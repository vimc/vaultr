##' Make a vault client.  This must be done before accessing the
##' vault.  The default values for arguments are controlled by
##' environment variables (see Details) and values provided as
##' arguments override these defaults.
##'
##' @section Environment variables:
##'
##' The creation of a client is affected by a number of environment
##'   variables, following the main vault command line client.
##'
##' * `VAULT_ADDR`: The url of the vault server.  Must
##'   include a protocol (most likely `https://` but in testing
##'   `http://` might be used)
##'
##' * `VAULT_CAPATH`: The path to CA certificates
##'
##' * `VAULT_TOKEN`: A vault token to use in authentication.
##'   Only used for token-based authentication
##'
##' * `VAULT_AUTH_GITHUB_TOKEN`: As for the command line
##'   client, a github token for authentication using the github
##'   authentication backend
##'
##' * `VAULTR_AUTH_METHOD`: The method to use for
##'   authentication
##'
##' @title Make a vault client
##'
##' @param login Login method.  Specify a string to be passed along as
##'   the `method` argument to `$login`.  The default
##'   `FALSE` means not to login.  `TRUE` means to login
##'   using a default method specified by the environment variable
##'   `VAULTR_AUTH_METHOD` - if that variable is not set, an
##'   error is thrown.  The value of `NULL` is the same as
##'   `TRUE` but does not throw an error if
##'   `VAULTR_AUTH_METHOD` is not set.  Supported methods are
##'   `token`, `github` and `userpass`.
##'
##' @param ... Additional arguments passed along to the authentication
##'   method indicated by `login`, if used.
##'
##' @param addr The vault address *including protocol and port*,
##'   e.g., `https://vault.example.com:8200`.  If not given, the
##'   default is the environment variable `VAULT_ADDR`, which is
##'   the same as used by vault's command line client.
##'
##' @param tls_config TLS (https) configuration.  For most uses this
##'   can be left blank.  However, if your vault server uses a
##'   self-signed certificate you will need to provide this.  Defaults
##'   to the environment variable `VAULT_CAPATH`, which is the
##'   same as vault's command line client.
##'
##' @param namespace A [vault
##'   namespace](https://developer.hashicorp.com/vault/tutorials/enterprise/namespaces),
##'   when using enterprise vault. If given, then this must a string,
##'   and your vault must support namespaces, which is an enterprise
##'   feature. If the environment variable `VAULT_NAMESPACE` is set,
##'   we use that namespace when `NULL` is provided as an argument
##'   (this is the same variable as used by vault's command line
##'   client).
##'
##' @export
##' @author Rich FitzJohn
##' @examples
##'
##'
##' # We work with a test vault server here (see ?vault_test_server) for
##' # details.  To use it, you must have a vault binary installed on your
##' # system.  These examples will not affect any real running vault
##' # instance that you can connect to.
##' server <- vaultr::vault_test_server(if_disabled = message)
##'
##' if (!is.null(server)) {
##'   # Create a vault_client object by providing the address of the vault
##'   # server.
##'   client <- vaultr::vault_client(addr = server$addr)
##'
##'   # The client has many methods, grouped into a structure:
##'   client
##'
##'   # For example, token related commands:
##'   client$token
##'
##'   # The client is not authenticated by default:
##'   try(client$list("/secret"))
##'
##'   # A few methods are unauthenticated and can still be run
##'   client$status()
##'
##'   # Login to the vault, using the token that we know from the server -
##'   # ordinarily you would use a login approach suitable for your needs
##'   # (see the vault documentation).
##'   token <- server$token
##'   client$login(method = "token", token = token)
##'
##'   # The vault contains no secrets at present
##'   client$list("/secret")
##'
##'   # Secrets can contain any (reasonable) number of key-value pairs,
##'   # passed in as a list
##'   client$write("/secret/users/alice", list(password = "s3cret!"))
##'
##'   # The whole list can be read out
##'   client$read("/secret/users/alice")
##'   # ...or just a field
##'   client$read("/secret/users/alice", "password")
##'
##'   # Reading non-existant values returns NULL, not an error
##'   client$read("/secret/users/bob")
##'
##'   client$delete("/secret/users/alice")
##' }
vault_client <- function(login = FALSE, ..., addr = NULL, tls_config = NULL,
                         namespace = NULL) {
  client <- vault_client_$new(addr, tls_config, namespace)
  method <- vault_client_login_method(login)
  if (!is.null(method)) {
    client$login(..., method = method)
  }
  client
}


##' @rdname vault_client
vault_client_ <- R6::R6Class(
  "vault_client",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL),

  public = list(
    ##' @field auth Authentication backends: [vaultr::vault_client_auth]
    auth = NULL,

    ##' @field audit Audit methods: [vaultr::vault_client_audit]
    audit = NULL,

    ##' @field cubbyhole The vault cubbyhole key-value store:
    ##'   [vaultr::vault_client_cubbyhole]
    cubbyhole = NULL,

    ##' @field operator Operator methods: [vaultr::vault_client_operator]
    operator = NULL,

    ##' @field policy Policy methods: [vaultr::vault_client_policy]
    policy = NULL,

    ##' @field secrets Secret backends: [vaultr::vault_client_secrets]
    secrets = NULL,

    ##' @field token Token methods: [vaultr::vault_client_token]
    token = NULL,

    ##' @field tools Vault tools: [vaultr::vault_client_tools]
    tools = NULL,

    ##' @description Create a new vault client. Not typically called
    ##'   directly, but via the `vault_client` method.
    ##'
    ##' @param addr The vault address, including protocol and port
    ##'
    ##' @param tls_config The TLS config, if used
    ##'
    ##' @param namespace The namespace, if used
    initialize = function(addr, tls_config, namespace) {
      super$initialize("core methods for interacting with vault")
      api_client <- vault_api_client$new(addr, tls_config, namespace)

      private$api_client <- api_client

      add_const_member(self, "auth", vault_client_auth$new(api_client))
      add_const_member(self, "audit", vault_client_audit$new(api_client))
      add_const_member(self, "operator", vault_client_operator$new(api_client))
      add_const_member(self, "policy", vault_client_policy$new(api_client))
      add_const_member(self, "secrets", vault_client_secrets$new(api_client))
      add_const_member(self, "token", vault_client_token$new(api_client))
      add_const_member(self, "tools", vault_client_tools$new(api_client))
    },

    ##' @description Returns an api client object that can be used to
    ##'   directly interact with the vault server.
    api = function() {
      private$api_client
    },

    ## Root object kv1 methods
    ##' @description Read a value from the vault.  This can be used to
    ##'   read any value that you have permission to read, and can also
    ##'   be used as an interface to a version 1 key-value store (see
    ##'   [vaultr::vault_client_kv1].  Similar to the vault CLI command
    ##'   `vault read`.
    ##'
    ##' @param path Path for the secret to read, such as
    ##'   `/secret/mysecret`
    ##'
    ##' @param field Optional field to read from the secret.  Each
    ##'   secret is stored as a key/value set (represented in R as a
    ##'   named list) and this is equivalent to using `[[field]]` on
    ##'   the return value.  The default, `NULL`, returns the full set
    ##'   of values.
    ##'
    ##' @param metadata Logical, indicating if we should return
    ##'   metadata for this secret (lease information etc) as an
    ##'   attribute along with the values itself.  Ignored if `field`
    ##'   is specified.
    read = function(path, field = NULL, metadata = FALSE) {
      self$secrets$kv1$read(path, field, metadata)
    },

    ##' @description Write data into the vault.  This can be used to
    ##'   write any value that you have permission to write, and can
    ##'   also be used as an interface to a version 1 key-value store
    ##'   (see [vaultr::vault_client_kv1].  Similar to the vault CLI
    ##'   command `vault write`.
    ##'
    ##' @param path Path for the secret to write, such as
    ##'   `/secret/mysecret`
    ##'
    ##' @param data A named list of values to write into the vault at
    ##'    this path.  This *replaces* any existing values.
    write = function(path, data) {
      self$secrets$kv1$write(path, data)
    },

    ##' @description Delete a value from the vault
    ##'
    ##' @param path The path to delete
    delete = function(path) {
      self$secrets$kv1$delete(path)
    },

    ## NOTE: no recursive list here
    ##' @description List data in the vault at a given path.  This can
    ##'   be used to list keys, etc (e.g., at `/secret`).
    ##'
    ##' @param path The path to list
    ##
    ##' @param full_names Logical, indicating if full paths (relative
    ##'   to the vault root) should be returned.
    ##'
    ##' @return A character vector (of zero length if no keys are
    ##'   found).  Paths that are "directories" (i.e., that contain
    ##'   keys and could themselves be listed) will be returned with a
    ##'   trailing forward slash, e.g. `path/`
    list = function(path, full_names = FALSE) {
      self$secrets$kv1$list(path, full_names)
    },

    ##' @description Login to the vault.  This method is more
    ##'   complicated than most.
    ##'
    ##' @param ...  Additional named parameters passed through to the
    ##'   underlying method
    ##'
    ##' @param method Authentication method to use, as a string.
    ##'   Supported values include `token` (the default), `github`,
    ##'   `approle` and `userpass`.
    ##'
    ##' @param mount The mount path for the authentication backend, *if
    ##'   it has been mounted in a nonstandard location*.  If not
    ##'   given, then it is assumed that the backend was mounted at a
    ##'   path corresponding to the method name.
    ##'
    ##' @param renew Login, even if we appear to hold a valid token.
    ##'   If `FALSE` and we have a token then `login` does nothing.
    ##'
    ##' @param quiet Suppress some informational messages
    ##'
    ##' @param token_only Logical, indicating that we do not want to
    ##'   actually log in, but instead just generate a token and return
    ##'   that.  IF given then `renew` is ignored and we always
    ##'   generate a new token.
    ##'
    ##' @param use_cache Logical, indicating if we should look in the
    ##'   session cache for a token for this client.  If this is `TRUE`
    ##'   then when we log in we save a copy of the token for this
    ##'   session and any subsequent calls to `login` at this vault
    ##'   address that use `use_cache = TRUE` will be able to use this
    ##'   token.  Using cached tokens will make using some
    ##'   authentication backends that require authentication with
    ##'   external resources (e.g., `github`) much faster.
    login = function(..., method = "token", mount = NULL,
                     renew = FALSE, quiet = FALSE,
                     token_only = FALSE, use_cache = TRUE) {
      do_auth <-
        assert_scalar_logical(renew) ||
        assert_scalar_logical(token_only) ||
        !private$api_client$is_authenticated()
      if (!do_auth) {
        return(NULL)
      }

      auth <- self$auth[[method]]
      if (!inherits(auth, "R6")) {
        stop(sprintf(
          "Unknown login method '%s' - must be one of %s",
          method, paste(squote(self$auth$backends()), collapse = ", ")),
          call. = FALSE)
      }
      if (!is.null(mount)) {
        if (method == "token") {
          stop("method 'token' does not accept a custom mount")
        }
        auth <- auth$custom_mount(mount)
      }

      ## TODO: Feedback usage information here on failure?
      assert_scalar_character(method)
      assert_named(list(...), "...")
      if (method == "token") {
        token <- auth$login(..., quiet = quiet)
      } else {
        token <- vault_env$cache$get(private$api_client,
                                     use_cache && !token_only)
        if (is.null(token)) {
          data <- auth$login(...)
          if (!quiet) {
            message(pretty_lease(data$lease_duration))
          }
          token <- data$client_token
          if (!token_only) {
            vault_env$cache$set(private$api_client, token, use_cache)
          }
        }
      }

      if (!token_only) {
        private$api_client$set_token(token)
      }

      invisible(token)
    },

    ##' @description Return the status of the vault server, including
    ##'   whether it is sealed or not, and the vault server version.
    status = function() {
      self$operator$seal_status()
    },

    ##' @description Returns the original response inside the given
    ##'   wrapping token. The vault endpoints used by this method
    ##'   perform validation checks on the token, returns the original
    ##'   value on the wire rather than a JSON string representation of
    ##'   it, and ensures that the response is properly audit-logged.
    ##'
    ##' @param token Specifies the wrapping token ID
    unwrap = function(token) {
      assert_scalar_character(token)
      private$api_client$POST("/sys/wrapping/unwrap", token = token)
    },

    ##' @description Look up properties of a wrapping token.
    ##'
    ##' @param token Specifies the wrapping token ID to lookup
    wrap_lookup = function(token) {
      assert_scalar_character(token)
      private$api_client$POST("/sys/wrapping/lookup", token = token,
                              allow_missing_token = TRUE)$data
    }
  ))


vault_client_login_method <- function(login) {
  if (isFALSE(login)) {
    return(NULL)
  }
  if (is.null(login) || isTRUE(login)) {
    required <- isTRUE(login)
    login <- Sys_getenv("VAULTR_AUTH_METHOD", NULL)
    if (is.null(login)) {
      if (required) {
        stop("Default login method not set in 'VAULTR_AUTH_METHOD'",
             call. = FALSE)
      } else {
        return(NULL)
      }
    }
  }
  assert_scalar_character(login)
  login
}
