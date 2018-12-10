R6_vault_client_token <- R6::R6Class(
  "vault_client_token",

  private = list(
    api_client = NULL
  ),

  public = list(
    initialize = function(api_client) {
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "token",
                          "Interact and configure vault's token support")
    },

    list = function() {
      dat <- private$api_client$LIST("/auth/token/accessors")
      list_to_character(dat$data$keys)
    },

    capabilities = function(path, token) {
      body <- list(paths = I(assert_character(path)),
                   token = assert_scalar_character(token))
      data <- private$api_client$POST("/sys/capabilities", body = body)
      lapply(data$data[path], list_to_character)
    },

    capabilities_self = function(path) {
      body <- list(paths = I(assert_character(path)))
      data <- private$api_client$POST("/sys/capabilities-self", body = body)
      lapply(data$data[path], list_to_character)
    },

    capabilities_accessor = function(path, accessor) {
      body <- list(paths = I(assert_character(path)),
                   accessor = assert_scalar_character(accessor))
      data <- private$api_client$POST("/sys/capabilities-accessor", body = body)
      lapply(data$data[path], list_to_character)
    },

    client = function() {
      private$api_client$token
    },

    create = function(role_name = NULL, id = NULL, policies = NULL,
                      meta = NULL, orphan = FALSE, no_default_policy = FALSE,
                      max_ttl = NULL, display_name = NULL,
                      use_limit = 0L, period = NULL, ttl = NULL) {
      body <- list(
        role_name = role_name %&&% assert_scalar_character(role_name),
        policies = policies %&&% I(assert_character(policies)),
        meta = meta,
        no_default_policy = assert_scalar_logical(no_default_policy),
        explicit_max_ttl = max_ttl %&&% assert_is_duration(max_ttl),
        display_name = display_name %&&% assert_scalar_character(display_name),
        num_uses = use_limit %&&% assert_scalar_integer(use_limit),
        ttl = ttl %&&% assert_is_duration(ttl),
        ## root only:
        id = role_name %&&% assert_scalar_character(id),
        period = period %&&% assert_is_duration(period),
        no_parent = assert_scalar_logical(orphan))
      body <- drop_null(body)
      res <- private$api_client$POST("/auth/token/create", body = body)

      info <- res$auth
      info$policies <- list_to_character(info$policies)
      token <- info$client_token
      attr(token, "info") <- info
      token
    },

    lookup = function(token = NULL) {
      body <- list(token = assert_scalar_character(token))
      res <- private$api_client$POST("/auth/token/lookup", body = body)
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

    lookup_self = function() {
      res <- private$api_client$GET("/auth/token/lookup-self")
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

    lookup_accessor = function(accessor) {
      body <- list(accessor = assert_scalar_character(accessor))
      res <- private$api_client$POST("/auth/token/lookup-accessor", body = body)
      data <- res$data
      data$policies <- list_to_character(data$policies)
      data
    },

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

    renew_self = function(increment = NULL) {
      body <- list(
        increment = increment %&&% assert_is_duration(increment))
      res <- private$api_client$POST("/auth/token/renew-self",
                                     body = drop_null(body))
      info <- res$auth
      info$policies <- list_to_character(info$policies)
      info
    },

    revoke = function(token) {
      body <- list(token = assert_scalar_character(token))
      private$api_client$POST("/auth/token/revoke", body = body)
      invisible(NULL)
    },

    revoke_self = function() {
      private$api_client$POST("/auth/token/revoke-self")
      invisible(NULL)
    },

    revoke_accessor = function(accessor) {
      body <- list(accessor = assert_scalar_character(accessor))
      private$api_client$POST("/auth/token/revoke-accessor", body = body)
      invisible(NULL)
    },

    revoke_and_orphan = function(token) {
      body <- list(token = assert_scalar_character(token))
      private$api_client$POST("/auth/token/revoke-orphan", body = body)
      invisible(NULL)
    },

    role_read = function(role_name) {
      path <- sprintf("/auth/token/roles/%s",
                      assert_scalar_character(role_name))
      data <- private$api_client$GET(path)$data
      data$allowed_policies <- list_to_character(data$allowed_policies)
      data$disallowed_policies <- list_to_character(data$disallowed_policies)
      data
    },

    role_list = function() {
      dat <- tryCatch(private$api_client$LIST("/auth/token/roles"),
                      vault_invalid_path = function(e) NULL)
      list_to_character(dat$data$keys)
    },

    role_update = function(role_name, allowed_policies = NULL,
                           disallowed_policies = NULL, orphan = NULL,
                           period = NULL, renewable = NULL,
                           explicit_max_ttl = NULL, path_suffix = NULL,
                           bound_cidrs = NULL, service_type = NULL) {
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
        service_type = service_type %&&% assert_scalar_character(service_type))
      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    role_delete = function(role_name) {
      path <- sprintf("/auth/token/roles/%s",
                      assert_scalar_character(role_name))
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    tidy = function() {
      private$api_client$POST("/auth/token/tidy")
      invisible(NULL)
    }
  ))
