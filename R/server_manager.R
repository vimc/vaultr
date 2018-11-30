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
##' download a ~100MB binary from \url{https://vaultproject.io} so use
##' with care.  It is intended \emph{only} for use in automated
##' testing environments.
##'
##' @title Control a test vault server
##' @export
##' @rdname vault_test_server
vault_test_server <- function(https = FALSE) {
  vault_server_manager()$new_server(https)
}


##' @rdname vault_test_server
##'
##' @param quiet Suppress progress bars on install
##'
##' @param version Version of vault to install
##'
##' @export
vault_test_server_install <- function(quiet = FALSE, version = "0.10.3") {
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


vault_server_manager <- function() {
  if (is.null(vault_env$server_manager)) {
    bin <- vault_server_manager_bin()
    port <- vault_server_manager_port()
    vault_env$server_manager <- R6_vault_server_manager$new(bin, port)
  }
  vault_env$server_manager
}


vault_server_manager_bin <- function() {
  if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
    return(NULL)
  }
  path <- Sys_getenv("VAULT_BIN_PATH", NULL)
  if (is.null(path)) {
    return(NULL)
  }
  if (!file.exists(path) || !is_directory(path)) {
    return(NULL)
  }
  bin <- file.path(path, "vault")
  if (!file.exists(bin)) {
    return(NULL)
  }
  normalizePath(bin, mustWork = TRUE)
}


vault_server_manager_port <- function() {
  port <- Sys.getenv("VAULTR_TEST_SERVER_PORT", NA_character_)
  if (is.na(port)) {
    return(18200L)
  }
  if (!grepl("^[0-9]+$", port)) {
    stop(sprintf("Invalid port '%s'", port))
  }
  as.integer(port)
}


R6_vault_server_manager <- R6::R6Class(
  "vault_server_manager",

  public = list(
    bin = NULL,
    port = NULL,
    enabled = FALSE,

    initialize = function(bin, port = 18200L) {
      if (is.null(bin)) {
        self$enabled <- FALSE
      } else {
        assert_scalar_character(bin)
        assert_scalar_integer(port)
        self$bin <- normalizePath(bin, mustWork = TRUE)
        self$port <- port
        self$enabled <- TRUE
      }
    },

    new_port = function() {
      ret <- free_port(self$port)
      self$port <- self$port + 1L
      ret
    },

    new_server = function(https = FALSE) {
      if (!self$enabled) {
        testthat::skip("vault server is not enabled")
      }
      tryCatch(
        vault_server_instance$new(self$bin, self$new_port(), https),
        error = function(e)
          testthat::skip(paste("vault server failed to start:",
                               e$message)))
    }
  ))


vault_server_instance <- R6::R6Class(
  "vault_server_instance",

  public = list(
    port = NULL,

    process = NULL,
    addr = NULL,

    token = NULL,
    keys = NULL,

    initialize = function(bin, port, https = FALSE) {
      assert_scalar_integer(port)
      self$port <- port

      bin <- normalizePath(bin, mustWork = TRUE)
      if (https) {
        dat <- vault_server_start_https(bin, self$port)
      } else {
        dat <- vault_server_start_dev(bin, self$port)
      }

      for (i in names(dat)) {
        self[[i]] <- dat[[i]]
      }
    },

    client = function(login = TRUE, quiet = TRUE) {
      cl <- vault_client2(self$addr)
      if (login) {
        cl$login(token = self$token, quiet = quiet)
      }
      cl
    },

    finalize = function() {
      if (!is.null(self$process)) {
        self$process$kill()
      }
    },

    kill = function() {
      self$process$kill()
      self$process <- NULL
    }
  ))



fake_token <- function() {
  data <- sample(c(0:9, letters[1:6]), 32, TRUE)
  n <- c(8, 4, 4, 4, 12)
  paste(vcapply(split(data, rep(seq_along(n), n)), paste0, collapse = "",
                USE.NAMES = FALSE), collapse = "-")
}


vault_server_wait <- function(test, process, timeout = 5, poll = 0.05) {
  t1 <- Sys.time() + timeout
  repeat {
    ok <- tryCatch(test(), error = function(e) FALSE)
    if (ok) {
      break
    }
    if (!process$is_alive() || Sys.time() > t1) {
      err <- paste(readLines(process$get_error_file()), collapse = "\n")
      stop("vault has died: ", err)
    }
    message("...waiting for Vault to start")
    Sys.sleep(0.1)
  }
}


vault_server_start_dev <- function(bin, port) {
  token <- fake_token()
  args <- c("server", "-dev",
            sprintf("-dev-listen-address=127.0.0.1:%s", port),
            sprintf("-dev-root-token-id=%s", token))
  stdout <- tempfile()
  stderr <- tempfile()
  process <-
    processx::process$new(bin, args, stdout = stdout, stderr = stderr)
  on.exit(process$kill())

  addr <- sprintf("http://127.0.0.1:%d", port)

  cl <- vault_client2(addr)
  vault_server_wait(cl$operator$is_initialized, process)
  on.exit()

  txt <- readLines(process$get_output_file())
  re <- "\\s*Unseal Key:\\s+([^ ]+)\\s*$"
  i <- grep(re, txt)
  key <- NULL
  if (length(i) == 1L) {
    key <- sub(re, "\\1", txt[[i]])
  }

  ## See https://www.vaultproject.io/docs/secrets/kv/kv-v2.html#setup
  ##
  ## > when running a dev-mode server, the v2 kv secrets engine is
  ## > enabled by default at the path secret/ (for non-dev servers, it
  ## > is currently v1)
  cl$login(token = token, quiet = TRUE)
  info <- cl$secrets$list()

  description <- info$description[info$path == "secret/"]
  cl$secrets$disable("/secret")
  cl$secrets$enable("kv", "/secret", description, 1L)

  list(process = process,
       addr = addr,
       keys = key,
       token = token)
}


vault_server_start_https <- function(bin, port, init) {
  ## Create a server configuration:
  config_path <- system.file("server", package = "vaultr", mustWork = TRUE)
  cfg <- readLines(file.path(config_path, "vault-tls.hcl"))
  tr <- c(VAULT_CONFIG_PATH = config_path,
          VAULT_ADDR = sprintf("127.0.0.1:%s", port))
  path <- tempfile()
  writeLines(strsub(cfg, tr), path)

  args <- c("server", paste0("-config=", path))
  stdout <- tempfile()
  stderr <- tempfile()
  process <- processx::process$new(bin, args, stdout = stdout, stderr = stderr)
  on.exit(process$kill())

  addr <- sprintf("https://127.0.0.1:%d", port)
  cl <- vault_client2(addr, cacert)

  ## Here, our test function is a bit different because we're not
  ## expecting the server to be *initialised*, just to be ready to
  ## accept connections
  vault_server_wait(function() !cl$operator$is_initialized(), process)

  n <- 3
  t <- 2
  res <- cl$sys$init(n, t)
  keys <- res$keys_base64
  for (i in seq_len(t)) {
    cl$sys$unseal(keys[[i]])
  }

  on.exit()

  list(process = process,
       addr = addr,
       token = res$root_token,
       keys = keys)
}


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


vault_install <- function(dest, quiet, version) {
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
