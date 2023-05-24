##' Interact with vault's ldap authentication backend.
##' This backend can be used to configure ldap authentication, used in
##' some professional settings.  For more information,
##' please see the vault documentation
##' https://developer.hashicorp.com/vault/docs/auth/ldap
##'
##' @title Vault LDAP Authentication Configuration
##' @name vault_client_auth_ldap
##'
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   root <- server$client()
##'
##'   # The ldap authentication backend is not enabled by default,
##'   # so we need to enable it first
##'   root$auth$enable("ldap")
##'
##'   # Then we can add users:
##'   root$auth$ldap$write("alice", "p4ssw0rd")
##'
##'   # Create a new client and login with this user:
##'   alice <- vaultr::vault_client(addr = server$addr)
##'   # it is not recommended to login with the password like this as
##'   # it will end up in the command history, but in interactive use
##'   # you will be prompted securely for password
##'   alice$login(method = "ldap",
##'               username = "alice", password = "p4ssw0rd")
##'   # Alice has now logged in and has only "default" policies
##'   alice$auth$token$lookup_self()$policies
##'
##'   # (wheras our original root user has the "root" policy)
##'   root$auth$token$lookup_self()$policies
##' }
vault_client_auth_ldap <- R6::R6Class(
  "vault_client_auth_ldap",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    ##' @description Create a `vault_client_ldap` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    ##'
    ##' @param mount Mount point for the backend, should be "ldap" by default
    initialize = function(api_client, mount) {
      super$initialize("Interact and configure vault's ldap support")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Set up a `vault_client_auth_ldap` object at a
    ##'   custom mount.  For example, suppose you mounted the
    ##'   `ldap` authentication backend at `/ldap2` you might
    ##'   use `up <- vault$auth$ldap2$custom_mount("/ldap2")` -
    ##'   this pattern is repeated for other secret and authentication
    ##'   backends.
    ##'
    ##' @param mount String, indicating the path that the engine is mounted at.
    custom_mount = function(mount) {
      vault_client_auth_ldap$new(private$api_client, mount)
    },

    ##' @description Configures the connection parameters for
    ##'   ldap-based authentication.
    ##'
    ##' @param user_dn Base DN under which to perform user search.
    ##'   Example: ou=Users,dc=example,dc=com
    ##'
    ##' @param group_dn LDAP search base to use for group membership search.
    ##'   This can be the root containing either groups or users.
    ##'   Example: ou=Groups,dc=example,dc=com
    ##'
    ##' @param base_url The LDAP server to connect to.
    ##'   Examples: ldap://ldap.myorg.com, ldaps://ldap.myorg.com:636.
    ##'   Multiple URLs can be specified with commas, e.g.
    ##'   ldap://ldap.myorg.com,ldap://ldap2.myorg.com; these will be tried
    ##'   in-order.
    ##'
    ##' @param case_sensitive_names (boolean) If set, user and group names
    ##'   assigned to policies within the backend will be case sensitive.
    ##'   Otherwise, names will be normalized to lower case. Case will still be
    ##'   preserved when sending the username to the LDAP server at login time;
    ##'   this is only for matching local user/group definitions.
    ##'
    ##' @param bind_dn Distinguished name of object to bind when performing
    ##'   user search. Example: cn=vault,ou=Users,dc=example,dc=com
    ##'
    ##' @param bind_pass Password to use along with binddn when performing user
    ##'   search.
    ##'
    ##' @param user_attr Attribute on user attribute object matching the
    ##'   username passed when authenticating.
    ##'   Examples: sAMAccountName, cn, uid
    ##'
    ##' @param discover_dn (boolean) Use anonymous bind to discover the
    ##'   bind DN of a user.
    ##'
    ##' @param deny_null_bind (boolean) This option prevents users from
    ##'   bypassing authentication when providing an empty password.
    ##'
    ##' @param upn_domain The userPrincipalDomain used to construct the UPN
    ##'   string for the authenticating user. The constructed UPN will appear
    ##'   as [username]@UPNDomain. Example: example.com, which will cause
    ##'   vault to bind as username@example.com.
    ##'
    ##' @param group_filter Go template used when constructing the group
    ##'   membership query. The template can access the following context
    ##'   variables: [UserDN, Username]. The default is
    ##'   `(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
    ##'   which is compatible with several common directory schemas.
    ##'   To support nested group resolution for Active Directory, instead
    ##'   use the following query:
    ##'   `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))`.
    ##'
    ##' @param group_attr LDAP attribute to follow on objects returned by
    ##'   groupfilter in order to enumerate user group membership.
    ##'   Examples: for groupfilter queries returning group objects, use: cn.
    ##'   For queries returning user objects, use: memberOf. The default is cn.
    ##'
    ##' @param use_token_groups (boolean) If true, groups are resolved through
    ##'   Active Directory tokens. This may speed up nested group membership
    ##'   resolution in large directories.
    ##'
    ##' @param ttl Duration after which authentication will be expired
    ##'
    ##' @param max_ttl Maximum duration after which authentication will
    ##'   be expired
    configure = function(user_dn = NULL, group_dn = NULL, base_url = NULL,
                         case_sensitive_names = NULL, bind_dn = NULL,
                         bind_pass = NULL, user_attr = NULL,
                         discover_dn = NULL, deny_null_bind = TRUE,
                         upn_domain = NULL, group_filter = NULL,
                         group_attr = NULL, use_token_groups = NULL,
                         ttl = NULL, max_ttl = NULL) {
      path <- sprintf("/auth/%s/config", private$mount)
      body <- list(user_dn = user_dn, group_dn = group_dn, base_url = base_url,
                   case_sensitive_names = case_sensitive_names, bind_dn = bind_dn,
                   bind_pass = bind_pass, user_attr = user_attr,
                   discover_dn = discover_dn, deny_null_bind,
                   upn_domain = upn_domain, group_filter = group_filter,
                   group_attr = group_attr, use_token_groups = use_token_groups,
                   ttl = ttl, max_ttl = max_ttl)
      private$api_client$POST(path, body = drop_null(body))
      invisible(TRUE)
    },

    ##' @description Reads the connection parameters for ldap-based
    ##'   authentication.
    configuration = function() {
      private$api_client$GET(sprintf("/auth/%s/config", private$mount))$data
    },

    ##' @description Create or update a user.
    ##'
    ##' @param name (string) The name of the LDAP group
    ##'
    ##' @param password Password for the user (required when creating a
    ##'   user only)
    ##'
    ##' @param policies Character vector of policies for the user
    ##'
    ##' @param ttl The lease duration which decides login expiration
    ##'
    ##' @param max_ttl Maximum duration after which login should expire
    ##'
    ##' @param bound_cidrs Character vector of CIDRs.  If set,
    ##'   restricts usage of the login and token to client IPs falling
    ##'   within the range of the specified CIDR(s).
    write_group = function(name, password = NULL, policies = NULL, ttl = NULL,
                          max_ttl = NULL, bound_cidrs = NULL) {
      name <- assert_scalar_character(name)
      body <- list(
        password = assert_scalar_character_or_null(password),
        policies = policies %&&%
          paste(assert_character(policies), collapse = ","),
        ttl = ttl %&&% assert_is_duration(ttl),
        max_ttl = max_ttl %&&% assert_is_duration(max_ttl),
        bound_cidrs = bound_cidrs %&&% I(assert_character(bound_cidrs)))
      path <- sprintf("/auth/%s/groups/%s", private$mount, name)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Read policies associated with a LDAP group.
    ##'
    ##' Supported methods:
    ##'   GET: /auth/{mount_point}/groups/{name}. Produces: 200 application/json
    ##'
    ##' @param name The name of the LDAP group
    ##'
    read_group = function(name) {
      assert_scalar_character(name)
      path <- sprintf("/auth/%s/groups/%s", private$mount, name)
      ret <- private$api_client$GET(path, body = list(name = name))$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    ##' @description Delete a LDAP group and policy association.
    ##'
    ##' Supported methods:
    ##'   DELETE: /auth/{mount_point}/groups/{name}. Produces: 204 (empty body)
    ##'
    ##' @param name The name of the LDAP group
    delete_group = function(name) {
      assert_scalar_character(name)
      path <- sprintf("/auth/%s/groups/%s", private$mount, name)
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    ##' @description List existing LDAP existing groups that have been created
    ##'   in this auth method.
    ##'
    ##'   Supported methods:
    ##'     LIST: /auth/{mount_point}/groups. Produces: 200 application/json
    list_groups = function() {
      path <- sprintf("/auth/%s/groups", private$mount)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    ##' @description Create or update LDAP users policies and group associations.
    ##'
    ##' Supported methods:
    ##'   POST: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)
    ##'
    ##' @param username The username of the LDAP user
    ##'
    ##' @param policies Character vector of policies for the user
    ##'
    ##' @param groups Character vector of groups for the user
    ##'
    ##' @param ttl The lease duration which decides login expiration
    ##'
    ##' @param max_ttl Maximum duration after which login should expire
    ##'
    ##' @param bound_cidrs Character vector of CIDRs.  If set,
    ##'   restricts usage of the login and token to client IPs falling
    ##'   within the range of the specified CIDR(s).
    write = function(username, policies = NULL, ttl = NULL,
                   max_ttl = NULL, bound_cidrs = NULL) {
      username <- assert_scalar_character(username)
      body <- list(
        password = assert_scalar_character_or_null(password),
        policies = policies %&&%
          paste(assert_character(policies), collapse = ","),
        groups = groups %&&%
          paste(assert_character(groups), collapse = ","),
        ttl = ttl %&&% assert_is_duration(ttl),
        max_ttl = max_ttl %&&% assert_is_duration(max_ttl),
        bound_cidrs = bound_cidrs %&&% I(assert_character(bound_cidrs)))
      path <- sprintf("/auth/%s/users/%s", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Read policies associated with a LDAP user.
    ##'
    ##' Supported methods:
    ##'   GET: /auth/{mount_point}/users/{username}. Produces: 200 application/json
    ##'
    ##' @param username Username to read
    read = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      ret <- private$api_client$GET(path)$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    ##' @description Delete a LDAP user and policy association.
    ##'
    ##' Supported methods:
    ##'   DELETE: /auth/{mount_point}/users/{username}. Produces: 204 (empty body)
    ##'
    ##' @param username The username of the LDAP user
    delete = function(username) {
      assert_scalar_character(username)
      path <- sprintf("/auth/%s/users/%s", private$mount, username)
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    ##' @description Update password for a user
    ##'
    ##' @param username Username for the user to update
    ##'
    ##' @param password New password for the user
    update_password = function(username, password) {
      assert_scalar_character(username)
      body <- list(password = assert_scalar_character(password))
      path <- sprintf("/auth/%s/users/%s/password", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description Update vault policies for a user
    ##'
    ##' @param username Username for the user to update
    ##'
    ##' @param policies Character vector of policies for this user
    update_policies = function(username, policies) {
      assert_scalar_character(username)
      body <- list(policies = paste(assert_character(policies),
                                    collapse = ","))
      path <- sprintf("/auth/%s/users/%s/policies", private$mount, username)

      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    ##' @description List users known to vault
    list = function() {
      path <- sprintf("/auth/%s/users", private$mount)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    ##' @description Log into the vault using username/password
    ##'   authentication.  Normally you would not call this directly
    ##'   but instead use `$login` with `method = "ldap"` and
    ##'   proving the `username` argument and optionally the `password`
    ##'   argument.  This function returns a vault token but does not
    ##'   set it as the client token.
    ##'
    ##' @param username Username to authenticate with
    ##'
    ##' @param password Password to authenticate with. If omitted or
    ##'   `NULL` and the session is interactive, the password will be
    ##'   prompted for.
    login = function(username, password = NULL) {
      data <- ldap_data(username, password)
      path <- sprintf("/auth/%s/login/%s", private$mount, username)
      body <- list(password = data$password)
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))


## Needs to be a free function so that we can mock out the password
## read reliably
ldap_data <- function(username, password) {
  assert_scalar_character(username, "username")
  if (is.null(password)) {
    msg <- sprintf("Password for '%s': ", username)
    password <- read_password(msg)
  }
  assert_scalar_character(password, "password")
  list(username = username, password = password)
}
