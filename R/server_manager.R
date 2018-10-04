## This is intended primarily for test use, but it might also be
## useful for other packages that want to use vault in their testing.

##' Control a server for use with testing.  This is designed to be
##' used only by other packages that wish to run tests against a vault
##' server.  You will need to set \code{VAULT_BIN_PATH} to point at
##' the directory containing the vault binary.
##'
##' The function \code{vault_test_server_install} will install a test
##' server, but \emph{only} if the user opts in by setting the
##' environment variable \code{VAULTR_TEST_SERVER_INSTALL} to
##' \code{"true"}, and by setting \code{VAULT_BIN_PATH} to the
##' directory where the binary should be downloaded to.  This will
##' download a ~50MB binary from \url{https://vaultproject.io} so use
##' with care.  It is intended \emph{only} for use in automated
##' testing environments.
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
    message("Not starting vault server")
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
##' @param quiet Suppress progress bars on install
##'
##' @param version Version of vault to install
##'
##' @export
vault_test_server_install <- function(quiet = FALSE, version = "0.7.3") {
  if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
    stop("Do not run this on CRAN")
  }
  if (!identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
    stop("Please read the documentation for vault_test_server_install")
  }
  path <- Sys_getenv("VAULT_BIN_PATH", NULL)
  if (is.null(path)) {
    stop("VAULT_BIN_PATH is not set")
  }
  dir.create(path, FALSE, TRUE)
  dest <- file.path(path, "vault")
  if (file.exists(dest)) {
    message("vault already installed at ", dest)
  } else {
    vault_install(path, quiet, version)
  }
  invisible(dest)
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

    bin_path <- Sys_getenv("VAULT_BIN_PATH", ".vault")
    bin <- file.path(bin_path, "vault")
    if (file.exists(bin)) {
      ret$bin <- normalizePath(bin)
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

    client = NULL,
    bin = NULL,

    keys = NULL,
    root_token = NULL,

    stdout = NULL,
    stderr = NULL,

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

      cacert <- file.path(config_path, "server-cert.pem")

      self$client <- self$new_client(auth = FALSE, addr = self$url,
                                     verify = cacert)
      res <- try(self$client$sys_is_initialized(), silent = TRUE)
      if (!inherits(res, "try-error")) {
        stop("vault is already running at ", self$url)
      }

      message("Starting vault server at ", self$address)
      args <- c("server", paste0("-config=", path))
      self$stdout <- tempfile()
      self$stderr <- tempfile()
      self$process <-
        processx::process$new(self$bin, args,
                              stdout = self$stdout, stderr = self$stderr)
      on.exit(self$process$kill())

      for (i in 1:20) {
        res <- try(self$client$sys_is_initialized(), silent = TRUE)
        if (!inherits(res, "try-error")) {
          Sys.setenv(VAULT_ADDR = self$url)
          Sys.setenv(VAULT_CAPATH = file.path(config_path, "server-cert.pem"))

          message("...vault server is now listening")
          on.exit()
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
      self$write_env()
      invisible(self)
    },

    sys_initialize = function() {
      if (!self$client$sys_is_initialized()) {
        message("Initializing vault")
        result <- self$client$sys_initialize()
        self$root_token <- result[["root_token"]]
        self$keys <- result[["keys"]]
        Sys.setenv(VAULT_TOKEN = self$root_token)
      }
    },

    unseal = function() {
      if (self$client$is_sealed()) {
        message("Unsealing vault")
        self$client$unseal_multi(self$keys)
      }
    },

    write_env = function(path = ".vault-env") {
      data <- c(VAULT_ADDR = self$url,
                VAULT_CAPATH = Sys.getenv("VAULT_CAPATH"),
                VAULT_TOKEN = self$root_token,
                VAULTR_AUTH_METHOD = "token")
      str <- sprintf("export %s=%s", names(data), unname(data))
      writeLines(str, path)
    },

    kill = function() {
      message("Stopping vault server")
      self$process$kill()
    },

    new_client = function(ctor = vault_client, auth = TRUE, ...) {
      ctor(auth_method = if (auth) NULL else FALSE, quiet = TRUE, ...)
    }
  ))


vault_platform <- function() {
  sysname <- Sys.info()[["sysname"]]
  switch(sysname,
         Darwin = "darwin",
         Windows = "windows",
         Linux = "linux",
         stop("Unknown sysname"))
}


vault_url <- function(version, platform = vault_platform(), arch = "amd64") {
  sprintf("https://releases.hashicorp.com/vault/%s/vault_%s_%s_%s.zip",
          version, version, platform, arch)
}


vault_install <- function(dest, quiet, version = "0.7.3") {
  dest_bin <- file.path(dest, "vault")
  if (!file.exists(dest_bin)) {
    message(sprintf("installing vault to '%s'", dest))
    url <- vault_url(version)
    zip <- download_file(url, quiet = quiet)
    tmp <- tempfile()
    dir.create(tmp)
    utils::unzip(zip, exdir = tmp)
    ok <- file.copy(file.path(tmp, "vault"), dest_bin)
    unlink(tmp, recursive = TRUE)
    file.remove(zip)
    Sys.chmod(dest_bin, "755")
  }
  invisible(dest_bin)
}
