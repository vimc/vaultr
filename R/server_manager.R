## This is intended primarily for test use, but it might also be
## useful for other packages that want to use vault in their testing.

vault_test_server_start <- function() {
  loadNamespace("testthat")
  server <- server_manager$new()
  if (server$can_run()) {
    vault_env$server <- server
    server$up()
  } else {
    NULL
  }
}

vault_test_server_stop <- function() {
  if (!is.null(vault_env$server)) {
    vault_env$server$kill()
  }
}

vault_test_server <- function() {
  vault_env$server
}

vault_test_client <- function(...) {
  vault_env$server$new_client(...)
}

server_manager <- R6::R6Class(
  "server_manager",

  public = list(
    address = NULL,
    config_path = NULL,
    client = NULL,
    vault_bin = NULL,

    keys = NULL,
    root_token = NULL,

    process = NULL,

    initialize = function() {
      if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
        return()
      }
      port <- Sys.getenv("VAULTR_TEST_SERVER_PORT", NA_character_)
      if (!is.na(port)) {
        if (!grepl("^[0-9]+$", port)) {
          stop(sprintf("Invalid port '%s'", port))
        }
        self$address <- sprintf("127.0.0.1:%s", port)
      }
      vault_bin <- Sys.which("vault")
      if (nzchar(vault_bin)) {
        self$vault_bin <- unname(vault_bin)
      }
    },
    can_run = function() {
      !is.null(self$address) && !is.null(self$vault_bin)
    },
    start = function() {
      if (is.na(self$address)) {
        stop("'VAULTR_TEST_SERVER_PORT' not set")
      }
      vault <- Sys.which("vault")
      if (!nzchar(vault)) {
        stop("vault executable not found")
      }

      ## Write out a temporary configuration
      config_path <- system.file("server", package = "vaultr", mustWork = TRUE)
      cfg <- readLines(file.path(config_path, "vault-tls.hcl"))
      tr <- c(VAULT_CONFIG_PATH = config_path,
              VAULT_ADDR = self$address)
      path <- tempfile()
      writeLines(strsub(cfg, tr), path)

      message("Starting vault server at ", self$address)
      args <- c("server", paste0("-config=", path))
      self$process <-
        processx::process$new(vault, args, stdout = "|", stderr = "|")
      on.exit(self$process$kill())

      vault_addr <- paste0("https://", self$address)
      self$client <- self$new_client(auth = FALSE, addr = vault_addr)
      for (i in 1:20) {
        res <- try(self$client$sys_is_initialized(), silent = TRUE)
        if (!inherits(res, "try-error")) {
          message("...vault server is now listening")
          on.exit()
          Sys.setenv(VAULT_ADDR = vault_addr)
          return(TRUE)
        }
        # nocov start
        if (!self$process$is_alive()) {
          err <- paste(self$process$read_all_output_lines(), collapse = "\n")
          stop("vault has died: ", err)
        }
        message("...waiting for Vault to start")
        Sys.sleep(0.1)
        # nocov end
      }
      stop("Unable to start vault") # nocov
    },
    up = function() {
      self$start()
      self$sys_initialize()
      self$unseal()
      invisible(self)
    },
    sys_initialize = function() {
      if (self$client$sys_is_initialized()) {
        stop("server is already initialized")
      }
      message("Initializing vault")
      result <- self$client$sys_initialize()
      self$root_token <- result[["root_token"]]
      self$keys <- result[["keys"]]
    },
    unseal = function() {
      if (self$client$is_sealed()) {
        message("Unsealing vault")
        self$client$unseal_multi(self$keys)
      }
    },
    kill = function() {
      message("Stopping vault server")
      self$process$kill()
    },
    new_client = function(ctor = vault_client, auth = TRUE, ...) {
      pem <- system.file("server/server-cert.pem", package = "vaultr",
                         mustWork = TRUE)
      ctor(auth = if (auth) "token" else NULL,
           token = self$root_token, quiet = TRUE, verify = pem, ...)
    }
  ))
