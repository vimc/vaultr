vault_client <- function(url = "https://localhost:8200",
                         token = NULL, cert = NULL, verify = NULL) {
  R6_vault_client$new(url, token, cert, verify)
}

vault_client_generic <- function(...) {
  vault_client(...)$generic()
}

R6_vault_client <- R6::R6Class(
  "vault_client",
  public = list(
    allow_redirects = NULL,
    token = NULL,
    url = NULL,
    cert = NULL,
    verify = NULL,

    initialize = function(url, token, cert, verify) {
      if (!is.null(token)) {
        self$.auth_set_token(token)
      }
      self$url <- paste0(url, "/v1")
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
    auth_github = function(gh_token = NULL, renew = FALSE) {
      if (!self$.auth_needed(renew)) {
        res <- self$.post("/auth/github/login",
                          body = list(token = vault_gh_token(gh_token)))
        self$.auth_set_token(res$auth$client_token)
      }
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
  public = list(
    vault = NULL,
    initialize = function(vault) {
      assert_is(vault, "vault_client")
      self$vault <- vault
    },

    read = function(path, field = NULL, info = FALSE) {
      check_path(path, "/secret/")
      self$vault$read(path, field, info)
    },

    write = function(path, data, ttl = NULL) {
      check_path(path, "/secret/")
      if (!is.null(ttl)) {
        data$ttl <- ttl
      }
      self$vault$write(path, data)
    },

    list = function(path, recursive = FALSE) {
      check_path(path, "/secret")
      self$vault$list(path, recursive)
    },

    delete = function(path) {
      check_path(path, "/secret/")
      self$vault$delete(path)
    }))

check_path <- function(path, starts_with) {
  assert_scalar_character(path)
  if (!identical(substr(path, 1L, nchar(starts_with)), starts_with)) {
    stop(sprintf("Expected path to start with '%s'", starts_with))
  }
}
