##' Make a vault client
##'
##' @title Make a vault client
##'
##' @param auth An authentication method (e.g., "github")
##'
##' @param ... Additional arguments passed through to the auth method
##'
##' @param addr Vault address, e.g. \code{https://localhost:8200}.  If
##'   not given, defaults to the environment variable
##'   \code{VAULT_ADDR}.
##'
##' @param cert Client certificate
##'
##' @param verify Server certificate
##'
##' @export
vault_client <- function(auth = NULL, ...,
                         addr = NULL, cert = NULL, verify = NULL) {
  cl <- R6_vault_client$new(addr, cert, verify)
  if (!is.null(auth)) {
    cl$auth(auth, ...)
  }
  cl
}

##' Make a vault client for the "generic" interface.  Provides a much
##' simpler interface than \code{vault_client}, with none of the
##' administration functions.
##' @title Make a generic vault client
##' @param ... Passed to \code{vault_client}
##' @export
vault_client_generic <- function(...) {
  vault_client(...)$generic()
}

R6_vault_client <- R6::R6Class(
  "vault_client",
  cloneable = FALSE,

  public = list(
    allow_redirects = NULL,
    token = NULL,
    url = NULL,
    cert = NULL,
    verify = NULL,
    client = NULL,

    initialize = function(addr, cert, verify) {
      self$client <- self
      self$url <- paste0(vault_addr(addr), "/v1")
      self$cert <- cert

      if (!is.null(verify)) {
        if (identical(as.vector(verify), FALSE)) {
          self$verify <- httr::config(ssl_verifypeer = 0, ssl_verifyhost = 0)
        } else {
          ## assert_scalar_character(verify) && file.exists
          self$verify <- httr::config(cainfo = verify)
        }
      }
    },

    ## Backends:
    generic = function() {
      R6_vault_client_generic$new(self)
    },

    ## Setup:
    sys_is_initialized = function() {
      self$.get("/sys/init")$initialized
    },
    sys_initialize = function(secret_shares = 5L, secret_threshold = 3,
                          pgp_keys = NULL) {
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold)
      if (!is.null(pgp_keys)) {
        assert_length(pgp_keys, 5)
        body$pgp_keys <- pgp_keys
      }
      self$.put("/sys/init", body = body)
    },

    ## Unseal:
    unseal = function(key) {
      self$.put("/sys/unseal", body = list(key = key))
    },

    unseal_multi = function(keys) {
      result <- NULL
      for (key in keys) {
        result <- self$unseal(key)
        if (!result$sealed) {
          break
        }
      }
      result
    },
    unseal_reset = function() {
      self$.put("/sys/unseal", body = list(reset = TRUE), to_json = TRUE)
    },
    seal = function() {
      self$.put("/sys/seal", to_json = FALSE)
      invisible()
    },
    seal_status = function() {
      self$.get("/sys/seal-status")
    },
    is_sealed = function() {
      self$seal_status()$sealed
    },

    ## System
    list_backends = function() {
      data <- self$.get("/sys/mounts")
      cols <- c("type", "local", "description", "config")
      ## This bit is needed because the output I see deviates from the
      ## API spec:
      ## https://github.com/hashicorp/vault/blob/master/api/SPEC.md
      ok <- vlapply(data$data, function(x) setequal(names(x), cols))
      if (!any(ok)) {
        stop("Unexpected output")
      }
      ret <- data_frame(
        name = sub("/$", "", names(data$data)),
        type = vcapply(data$data, "[[", "type", USE.NAMES = FALSE),
        local = vlapply(data$data, "[[", "local", USE.NAMES = FALSE),
        description = vcapply(data$data, "[[", "description",
                              USE.NAMES = FALSE))
      ret$config <- unname(lapply(data$data, "[[", "config"))
      ret
    },

    sys_leader_status = function() {
      self$.get("/sys/leader")
    },

    ## policy
    policy_list = function() {
      data <- self$.get("/sys/policy")
      lapply(data$data, list_to_character)
    },
    policy_read = function(name) {
      assert_scalar_character(name)
      self$.get(paste0("/sys/policy/", name))$data$rules
    },
    policy_write = function(name, rules) {
      assert_scalar_character(name)
      assert_scalar_character(rules)
      self$.put(paste0("/sys/policy/", name), body = list(rules = rules),
                to_json = FALSE)
      invisible(NULL)
    },

    ## Query
    read = function(path, field = NULL, info = FALSE) {
      assert_absolute_path(path)
      res <- tryCatch(self$.get(path),
                      vault_invalid_path = function(e) NULL)
      if (is.null(res)) {
        ret <- NULL
      } else {
        ret <- res$data
        if (!is.null(field)) {
          assert_scalar_character(field)
          ret <- res$data[[field]]
          if (is.null(ret)) {
            return(ret)
          }
        }
        if (info) {
          attr <- res[setdiff(names(res), "data")]
          attr(ret, "info") <- attr[lengths(attr) > 0]
        }
      }
      ret
    },
    list = function(path, recursive = FALSE) {
      assert_absolute_path(path)
      dat <- tryCatch(self$.get(path, query = list(list = TRUE)),
                      vault_invalid_path = function(e) NULL)

      ret <- file.path(sub("/+$", "", path),
                       list_to_character(dat$data$keys))

      if (recursive) {
        i <- grepl("/$", ret)
        if (any(i)) {
          new <- unlist(lapply(sub("/$", "", ret[i]), self$list, TRUE),
                        use.names = FALSE)
          ret <- sort(c(ret[!i], new))
        }
      }
      ret
    },
    write = function(path, data) {
      assert_named(data)
      res <- self$.post(path, body = data, to_json = FALSE)
      if (httr::status_code(res) == 200) {
        response_to_json(res)
      } else {
        invisible(NULL)
      }
    },
    delete = function(path) {
      assert_absolute_path(path)
      self$.delete(path, to_json = FALSE)
      invisible(NULL)
    },

    ## Auth
    auth = function(type, ..., renew = FALSE, quiet = FALSE) {
      switch(type,
             token = self$auth_token(..., renew = renew, quiet = quiet),
             github = self$auth_github(..., renew = renew, quiet = quiet),
             stop(sprintf("Unknown auth type '%s'", type)))
      invisible(self)
    },

    auth_token = function(token, renew = FALSE, quiet = TRUE) {
      if (self$.auth_needed(renew)) {
        assert_scalar_character_or_null(token)
        if (!quiet && !is.null(token)) {
          message("Authenticating using token")
        }
        self$.auth_set_token(token)
      }
    },

    auth_github = function(gh_token = NULL, renew = FALSE, quiet = FALSE) {
      if (self$.auth_needed(renew)) {
        if (!quiet) {
          message("Authenticating using github...", appendLF=FALSE)
        }
        gh_token <- vault_auth_github_token(gh_token)
        res <- self$.post("/auth/github/login", body = list(token = gh_token))
        self$.auth_set_token(res$auth$client_token)
        if (!quiet) {
          lease <- res$auth$lease_duration
          message(sprintf("ok, duration: %s s (%s)",
                          lease, prettyunits::pretty_sec(lease, TRUE)))
        }
      }
    },

    list_auth_backends = function() {
      data <- self$.get("/sys/auth")
      ret <- data_frame(
        name = sub("/$", "", names(data$data)),
        type = vcapply(data$data, "[[", "type", USE.NAMES = FALSE),
        local = vlapply(data$data, "[[", "local", USE.NAMES = FALSE),
        description = vcapply(data$data, "[[", "description",
                              USE.NAMES = FALSE))
      ret$config <- unname(lapply(data$data, "[[", "config"))
      ret
    },

    enable_auth_backend = function(type, description = NULL,
                                   mount_point = NULL) {
      if (is.null(mount_point)) {
        mount_point <- type
      }
      assert_scalar_character(type)
      assert_scalar_character_or_null(description)
      assert_scalar_character(mount_point)

      body <- list(type = type,
                   description = description)
      self$.post(paste0("/sys/auth/", mount_point), body = body,
                 to_json = FALSE)
      invisible(NULL)
    },

    disable_auth_backend = function(mount_point) {
      assert_scalar_character(mount_point)
      res <- self$.delete(paste0("/sys/auth/", mount_point), to_json = FALSE)
      invisible(NULL)
    },

    ## This all comes out
    config_auth_github_write = function(organization, base_url = NULL,
                                        ttl = NULL, max_ttl = NULL) {
      assert_scalar_character(organization)
      body <- list(organization = organization,
                   base_url = base_url,
                   ttl = ttl,
                   max_ttl = max_ttl)
      body <- body[!vlapply(body, is.null)]
      self$.post("/auth/github/config", body, to_json = FALSE)
      invisible(TRUE)
    },
    config_auth_github_read = function() {
      self$.get("/auth/github/config")$data
    },
    config_auth_github_write_policy = function(team, policy) {
      assert_scalar_character(team)
      assert_scalar_character(policy)
      self$.post(paste0("/auth/github/map/teams/", team),
                 body = list(value = policy), to_json = FALSE)
      invisible(NULL)
    },
    config_auth_github_read_policy = function(team) {
      assert_scalar_character(team)
      self$.get(paste0("/auth/github/map/teams/", team))$data$value
    },

    ## HTTP verbs
    .get = function(...) {
      vault_GET(self$url, self$verify, self$token, ...)
    },
    .put = function(...) {
      vault_PUT(self$url, self$verify, self$token, ...)
    },
    .post = function(...) {
      vault_POST(self$url, self$verify, self$token, ...)
    },
    .delete = function(...) {
      vault_DELETE(self$url, self$verify, self$token, ...)
    },
    .auth_needed = function(renew) {
      renew || is.null(self$token)
    },
    .auth_set_token = function(client_token) {
      self$token <- httr::add_headers("X-Vault-Token" = client_token)
    }
  ))

R6_vault_client_generic <- R6::R6Class(
  "vault_client_generic",
  cloneable = FALSE,

  public = list(
    vault = NULL,
    initialize = function(vault) {
      assert_is(vault, "vault_client")
      self$vault <- vault
    },

    read = function(path, field = NULL, info = FALSE) {
      assert_path_prefix(path, "/secret/")
      self$vault$read(path, field, info)
    },

    write = function(path, data, ttl = NULL) {
      assert_path_prefix(path, "/secret/")
      if (!is.null(ttl)) {
        data$ttl <- ttl
      }
      self$vault$write(path, data)
    },

    list = function(path, recursive = FALSE) {
      assert_path_prefix(path, "/secret") # NOTE: no trailing
      self$vault$list(path, recursive)
    },

    delete = function(path) {
      assert_path_prefix(path, "/secret/")
      self$vault$delete(path)
    },

    auth = function(...) {
      self$client$auth(...)
      invisible(self)
    }
  ))
