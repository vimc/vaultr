##' Make a vault client.  The defaults for arguments are controlled by
##' environment variables.
##'
##' @title Make a vault client
##'
##' @param auth_method An authentication method (e.g., "token",
##'   "github").  If \code{NULL}, we try the value of
##'   \code{VAULTR_AUTH_METHOD}, and if that is not set then
##'   authentication is not done.
##'
##' @param ... Additional arguments passed through to the auth method
##'
##' @param addr Vault address, e.g. \code{https://localhost:8200}.  If
##'   not given, defaults to the environment variable
##'   \code{VAULT_ADDR}
##'
##' @param verify Server certificate (or \code{VAULT_CAPATH})
##'
##' @export
vault_client <- function(auth_method = NULL, ..., addr = NULL, verify = NULL) {
  verify <- vault_arg(verify, "VAULT_CAPATH")
  ## TODO: this means that the auth 'verify' argument can't be used!

  cl <- R6_vault_client$new(addr, verify)
  cl$auth(auth_method, ...)
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
    verify = NULL,
    client = NULL,

    initialize = function(addr, verify) {
      self$client <- self
      self$url <- paste0(vault_addr(addr), "/v1")

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
      self$.get("/sys/init", allow_missing_token = TRUE)$initialized
    },
    sys_initialize = function(secret_shares = 5L, secret_threshold = 3,
                          pgp_keys = NULL) {
      body <- list(secret_shares = secret_shares,
                   secret_threshold = secret_threshold)
      if (!is.null(pgp_keys)) {
        assert_length(pgp_keys, 5)
        body$pgp_keys <- pgp_keys
      }
      self$.put("/sys/init", body = body,
                allow_missing_token = TRUE)
    },

    ## Unseal:
    unseal = function(key) {
      self$.put("/sys/unseal", body = list(key = key),
                allow_missing_token = TRUE)
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
      self$.put("/sys/unseal", body = list(reset = TRUE),
                to_json = TRUE, allow_missing_token = TRUE)
    },
    seal = function() {
      self$.put("/sys/seal", to_json = FALSE)
      invisible()
    },
    seal_status = function() {
      self$.get("/sys/seal-status", allow_missing_token = TRUE)
    },
    is_sealed = function() {
      self$seal_status()$sealed
    },

    ## System
    list_backends = function() {
      data <- self$.get("/sys/mounts")

      ## The colums returned here vary by version:
      ##
      ## 0.7.3 - type, local, description, config
      ## 0.8.1 - type, local, description, config, accessor
      ##
      cols <- names(data$data[[1]])
      ## sort out the orderig
      first <- c("type", "local", "description")
      cols <- c(first, setdiff(cols, c(first, "config")), "config")

      ok <- vlapply(data$data[-1], function(x) setequal(names(x), cols))
      if (!any(ok)) {
        stop("Unexpected output") # nocov
      }

      ret <- lapply(setdiff(cols, "config"), function(x)
        vapply(data$data, "[[", if (x == "local") FALSE else "", x,
               USE.NAMES = FALSE))
      names(ret) <- setdiff(cols, "config")
      ret <- c(list(name = sub("/$", "", names(data$data))), ret)
      ret <- as.data.frame(ret, stringsAsFactors = FALSE)
      ret$config <- lapply(data$data, "[[", "config")
      ret
    },

    sys_leader_status = function() {
      self$.get("/sys/leader")
    },

    ## policy
    policy_list = function() {
      data <- self$.get("/sys/policy")
      list_to_character(data$data$keys)
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
    policy_delete = function(name) {
      assert_scalar_character(name)
      self$.delete(paste0("/sys/policy/", name), to_json = FALSE)
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
    auth = function(method, ..., renew = FALSE, quiet = FALSE, verify = TRUE,
                    cache_dir = NULL) {
      method <- vault_arg(method, "VAULTR_AUTH_METHOD")
      if (is.null(method) || identical(method, FALSE)) {
        if (!quiet) {
          message("Not authenticating vault")
        }
        return(invisible(self))
      }
      assert_scalar_character(method)

      if (self$.auth_needed(renew)) {
        cache_dir <- vault_arg(cache_dir, "VAULTR_CACHE_DIR")
        use_cache <- !(is.null(cache_dir) || isFALSE(cache_dir))
        if (use_cache) {
          assert_scalar_character(cache_dir)
          cache_path <-
            file.path(cache_dir, base64url::base64_urlencode(self$url))
        }

        if (!renew && use_cache && file.exists(cache_path)) {
          if (!quiet) {
            message("Using cached token")
          }
          token <- rawToChar(cyphr::decrypt_file(cache_path, ssh_key()))
          self$.auth_set_token(token, verify)
        } else {
          fn <- switch(method,
                       token = self$auth_token,
                       github = self$auth_github,
                       stop(sprintf("Unknown auth method '%s'", method)))
          fn(..., quiet = quiet, verify = verify)

          if (use_cache) {
            dir.create(cache_dir, FALSE, TRUE)
            if (!quiet) {
              message("Saving (encrypted) token to cache")
            }
            cyphr::encrypt_string(self$token$headers[["X-Vault-Token"]],
                                  ssh_key(), cache_path)
          }
        }
      }

      invisible(self)
    },

    auth_token = function(token = NULL, quiet = TRUE, verify = TRUE) {
      token <- vault_arg(token, "VAULT_TOKEN")
      if (is.null(token)) {
        stop("token not found (check $VAULT_TOKEN environment variable)")
      }
      assert_scalar_character(token)
      if (!quiet && !is.null(token)) {
        message("Authenticating using token")
      }
      self$.auth_set_token(token, verify)
    },

    auth_github = function(gh_token = NULL, quiet = FALSE, verify = TRUE) {
      if (!quiet) {
        message("Authenticating using github...", appendLF=FALSE)
      }
      gh_token <- vault_auth_github_token(gh_token)
      res <- self$.post("/auth/github/login", body = list(token = gh_token),
                        allow_missing_token = TRUE)
      self$.auth_set_token(res$auth$client_token, verify)
      if (!quiet) {
        lease <- res$auth$lease_duration
        message(sprintf("ok, duration: %s s (%s)",
                        lease, prettyunits::pretty_sec(lease, TRUE)))
      }
    },

    is_authorized = function() {
      !is.null(self$token)
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
      self$.post("/auth/github/config", body = body, to_json = FALSE)
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
      vault_request(httr::GET, self$url, self$verify, self$token, ...)
    },
    .put = function(...) {
      vault_request(httr::PUT, self$url, self$verify, self$token, ...)
    },
    .post = function(...) {
      vault_request(httr::POST, self$url, self$verify, self$token, ...)
    },
    .delete = function(...) {
      vault_request(httr::DELETE, self$url, self$verify, self$token, ...)
    },

    .auth_needed = function(renew) {
      renew || is.null(self$token)
    },
    .auth_set_token = function(client_token, verify = TRUE) {
      token <- httr::add_headers("X-Vault-Token" = client_token)
      if (verify) {
        res <- httr::POST(paste0(self$url, "/sys/capabilities-self"),
                          self$verify, token,
                          body = list(path = "/sys/"), encode = "json")
        code <- httr::status_code(res)
        if (code >= 400) {
          stop(sprintf("Token verification failed with code %d", code))
        }
      }
      self$token <- token
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
      self$vault$auth(...)
      invisible(self)
    }
  ))


ssh_key <- function(private = TRUE) {
  if (is.null(vault_env$ssh_key)) {
    vault_env$ssh_key <- cyphr::keypair_openssl(NULL, NULL)
  }
  vault_env$ssh_key
}
