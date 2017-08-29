## This is intended primarily for test use, but it might also be
## useful for other packages that want to use vault in their testing.

##' Control a server for use with testing.  This is designed to be
##' used only by other packages that wish to run tests against a vault
##' server.
##'
##' The function \code{vault_test_server_install} will install a test
##' server, but \emph{only} if the user opts in by setting the
##' environment variable \code{VAULTR_TEST_SERVER_INSTALL} to
##' \code{"true"}.  This will download a ~50MB binary from
##' \url{https://vaultproject.io} so use with care.  It is intended
##' \emph{only} for use in automated testing environments.
##'
##' @title Control a test vault server
##' @export
##' @rdname vault_test_server
vault_test_server_start <- function() {
  server <- server_manager$new()
  if (server$can_run()) {
    vault_env$server <- server
    server$up()
  } else {
    NULL
  }
}

##' @rdname vault_test_server
##' @export
vault_test_server_stop <- function() {
  if (!is.null(vault_env$server)) {
    vault_env$server$kill()
  }
}

##' @rdname vault_test_server
##' @export
vault_test_server <- function() {
  vault_env$server
}

##' @rdname vault_test_server
##' @export
##' @param ... Argument passed through to create the new client
vault_test_client <- function(...) {
  if (!is.null(vault_env)) {
    vault_env$server$new_client(...)
  }
}

##' @rdname vault_test_server
##'
##' @param path Path to install the server to; must be an existing
##'   directory.
##'
##' @param quiet Suppress progress bars on install
##'
##' @export
vault_test_server_install <- function(path, quiet = FALSE) {
  if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
    stop("Do not run this on CRAN")
  }
  if (!identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
    stop("Please read the documentation for vault_test_server_install")
  }
  if (!isTRUE(file.info(path)$isdir)) {
    stop("'path' must be an existing directory")
  }
  install <- system.file("server/install-server.R", package = "vaultr",
                         mustWork = TRUE)
  ok <- system2(install, path, stdout = !quiet, stderr = !quiet)
  if (ok != 0L) {
    stop("Error installing vault server") # nocov
  }
  file.path(path, "vault")
}

vault_test_data <- function() {
  ret <- list(bin = NULL, port = NULL, address = NULL, url = NULL)
  if (identical(Sys.getenv("NOT_CRAN"), "true")) {
    port <- Sys.getenv("VAULTR_TEST_SERVER_PORT", NA_character_)
    if (!is.na(port)) {
      if (!grepl("^[0-9]+$", port)) {
        stop(sprintf("Invalid port '%s'", port))
      }
      ret$port <- port
      ret$address <- sprintf("127.0.0.1:%s", port)
      ret$url  <- sprintf("https://127.0.0.1:%s", port)
    }

    bin <- Sys.which("vault")
    if (nzchar(bin)) {
      ret$bin <- unname(bin)
    }
  }
  ret
}

server_manager <- R6::R6Class(
  "server_manager",

  public = list(
    port = NULL,
    address = NULL,
    url = NULL,

    config_path = NULL,
    client = NULL,
    bin = NULL,

    keys = NULL,
    root_token = NULL,

    process = NULL,

    initialize = function() {
      dat <- vault_test_data()
      self$bin <- dat$bin
      self$port <- dat$port
      self$address <- dat$address
      self$url <- dat$url
    },
    can_run = function() {
      !is.null(self$address) && !is.null(self$bin)
    },
    start = function() {
      if (is.null(self$bin)) {
        stop("vault executable not found")
      }
      if (is.null(self$address)) {
        stop("'VAULTR_TEST_SERVER_PORT' not set")
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
        processx::process$new(self$bin, args, stdout = "|", stderr = "|")
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
      if (!self$client$sys_is_initialized()) {
        message("Initializing vault")
        result <- self$client$sys_initialize()
        self$root_token <- result[["root_token"]]
        self$keys <- result[["keys"]]
      }
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
