##' Interact with vault's AppRole authentication backend.
##'
##' @template vault_client_auth_approle
##'
##' @title Vault AppRole Authentication Configuration
##' @name vault_client_auth_approle
NULL


R6_vault_client_auth_approle <- R6::R6Class(
  "vault_client_auth_approle",

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "approle",
                          "Interact and configure vault's AppRole support")
    },

    custom_mount = function(mount) {
      R6_vault_client_auth_approle$new(private$api_client, mount)
    },

    role_list = function() {
      path <- sprintf("/auth/%s/role", private$mount)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    role_write = function(role_name, bind_secret_id = NULL,
                          secret_id_bound_cidrs = NULL,
                          token_bound_cidrs = NULL,
                          policies = NULL,
                          secret_id_num_uses = NULL, secret_id_ttl = NULL,
                          token_num_uses = NULL, token_ttl = NULL,
                          token_max_ttl = NULL, period = NULL,
                          enable_local_secret_ids = NULL, token_type = NULL) {
      role_name <- assert_scalar_character(role_name)
      body <- list(
        bind_secret_id =
          bind_secret_id %&&% assert_scalar_boolean(bind_secret_id),
        secret_id_bound_cidrs =
          secret_id_bound_cidrs %&&% I(assert_character(secret_id_bound_cidrs)),
        token_bound_cidrs =
          token_bound_cidrs %&&% I(assert_character(token_bound_cidrs)),
        policies = policies %&&% paste(assert_character(policies),
                                       collapse = ","),
        secret_id_num_uses =
          secret_id_num_uses %&&% assert_scalar_integer(secret_id_num_uses),
        secret_id_ttl = secret_id_ttl %&&% assert_is_duration(secret_id_ttl),
        token_num_uses =
          token_num_uses %&&% assert_scalar_integer(token_num_uses),
        token_ttl = token_ttl %&&% assert_is_duration(token_ttl),
        token_max_ttl = token_max_ttl %&&% assert_is_duration(token_max_ttl),
        enable_local_secret_ids =
          enable_local_secret_ids %&&%
          assert_scalar_character(enable_local_secret_ids),
        period = period %&&% assert_is_duration(period),
        token_type = token_type %&&% assert_scalar_character(token_type))
      path <- sprintf("/auth/%s/role/%s", private$mount, role_name)
      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    role_read = function(role_name) {
      assert_scalar_character(role_name)
      path <- sprintf("/auth/%s/role/%s", private$mount, role_name)
      ret <- private$api_client$GET(path)$data
      ret$policies <- list_to_character(ret$policies)
      ret
    },

    role_delete = function(role_name) {
      assert_scalar_character(role_name)
      path <- sprintf("/auth/%s/role/%s", private$mount, role_name)
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    role_id_read = function(role_name) {
      assert_scalar_character(role_name)
      path <- sprintf("/auth/%s/role/%s/role-id", private$mount, role_name)
      private$api_client$GET(path)$data$role_id
    },

    role_id_write = function(role_name, role_id) {
      assert_scalar_character(role_name)
      body <- list(role_id = assert_scalar_character(role_id))
      path <- sprintf("/auth/%s/role/%s/role-id", private$mount, role_name)
      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    secret_id_generate = function(role_name, metadata = NULL,
                                  cidr_list = NULL, token_bound_cidrs = NULL) {
      assert_scalar_character(role_name)
      ## TODO: cidr_list interacts with bound_cidr_list but I don't
      ## see that as a parameter in the POST endpoints
      body <- list(
        metadata = metadata %&&% as.character(to_json(metadata)),
        cidr_list = cidr_list %&&% I(assert_character(cidr_list)),
        token_bound_cidrs =
          token_bound_cidrs %&&% I(assert_character(token_bound_cidrs)))
      path <- sprintf("/auth/%s/role/%s/secret-id", private$mount, role_name)
      res <- private$api_client$POST(path, body = body)
      list(id = res$data$secret_id, accessor = res$data$secret_id_accessor)
    },

    secret_id_list = function(role_name) {
      assert_scalar_character(role_name)
      path <- sprintf("/auth/%s/role/%s/secret-id", private$mount, role_name)
      tryCatch(
        list_to_character(private$api_client$LIST(path)$data$keys),
        vault_invalid_path = function(e) character(0))
    },

    secret_id_read = function(role_name, secret_id, accessor = FALSE) {
      assert_scalar_character(role_name)
      if (accessor) {
        path <- sprintf("/auth/%s/role/%s/secret-id-accessor/lookup",
                        private$mount, role_name)
        body <- list(secret_id_accessor = assert_scalar_character(secret_id))
      } else {
        path <- sprintf("/auth/%s/role/%s/secret-id/lookup",
                        private$mount, role_name)
        body <- list(secret_id = assert_scalar_character(secret_id))
      }
      private$api_client$POST(path, body = body)$data
    },

    secret_id_delete = function(role_name, secret_id, accessor = FALSE) {
      assert_scalar_character(role_name)
      if (accessor) {
        path <- sprintf("/auth/%s/role/%s/secret-id-accessor/destroy",
                        private$mount, role_name)
        body <- list(secret_id_accessor = assert_scalar_character(secret_id))
      } else {
        path <- sprintf("/auth/%s/role/%s/secret-id/destroy",
                        private$mount, role_name)
        body <- list(secret_id = assert_scalar_character(secret_id))
      }
      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    ## Create Custom AppRole Secret ID (push)
    ## Read, Update, or Delete AppRole Properties (separate here)
    ## Tidy Tokens

    login = function(role_id, secret_id) {
      body <- list(role_id = assert_scalar_character(role_id),
                   secret_id = assert_scalar_character(secret_id))
      path <- sprintf("/auth/%s/login", private$mount)
      res <- private$api_client$POST(path, body = body,
                                     allow_missing_token = TRUE)
      res$auth
    }
  ))
