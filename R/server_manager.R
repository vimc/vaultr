##' Control a server for use with testing.  This is designed to be
##' used only by other packages that wish to run tests against a vault
##' server.  You will need to set \code{VAULTR_TEST_SERVER_BIN_PATH} to
##' point at the directory containing the vault binary.
##'
##' The function \code{vault_test_server_install} will install a test
##' server, but \emph{only} if the user sets the following environmental
##' variables:
##' \itemize{
##'   \item \code{VAULTR_TEST_SERVER_INSTALL} to \code{"true"} to opt in
##' to the download.
##'   \item \code{VAULTR_TEST_SERVER_BIN_PATH} to the directory where 
##' the binary should be downloaded to.
##'   \item \code{NOT_CRAN} to \code{"true"} to indicate this is not running
##' on CRAN as it requires installation of a binary from a website.
##' }
##' This will download a ~100MB binary from \url{https://vaultproject.io}
##' so use with care.  It is intended \emph{only} for use in automated
##' testing environments.
##'
##' @title Control a test vault server
##'
##' @param https Logical scalar, indicating if a https-using server
##'   should be created, rather than the default vault dev-mode
##'   server.  This is still \emph{entirely} insecure, and uses self
##'   signed certificates that are bundled with the package.
##'
##' @param init Logical scalar, indicating if the https-using server
##'   should be initialised.
##'
##' @param if_disabled Callback function to run if the vault server is
##'   not enabled.  The default, designed to be used within tests, is
##'   \code{testthat::skip}.  Alternatively, inspect the
##'   \code{$enabled} property of the returned object.
##'
##' @export
##' @rdname vault_test_server
vault_test_server <- function(https = FALSE, init = TRUE,
                              if_disabled = testthat::skip) {
  vault_server_manager()$new_server(https, init, if_disabled)
}


##' @rdname vault_test_server
##'
##' @param quiet Suppress progress bars on install
##' @param path Path in which to install vault test server. Leave as NULL to use the 
##' \emph{VAULTR_TEST_SERVER_BIN_PATH} environment variable.
##' @param version Version of vault to install
##' @param platform For testing, overwrite the platform vault is being installed
##' on, with either "windows", "darwin" or "linux".
##'
##' @export
vault_test_server_install <- function(path = NULL, quiet = FALSE, 
                                      version = "1.0.0",
                                      platform = vault_platform()) {
  if (!identical(Sys.getenv("NOT_CRAN"), "true")) {
    stop("Do not run this on CRAN")
  }
  if (!identical(Sys.getenv("VAULTR_TEST_SERVER_INSTALL"), "true")) {
    stop("Please read the documentation for vault_test_server_install")
  }
  if (is.null(path)) {
    path <- Sys_getenv("VAULTR_TEST_SERVER_BIN_PATH", NULL)
    if (is.null(path)) {
      stop("VAULTR_TEST_SERVER_BIN_PATH is not set")
    }
  }
  
  dir_create(path)
  dest <- file.path(path, vault_exe_filename(platform))
  if (file.exists(dest)) {
    message("vault already installed at ", dest)
  } else {
    vault_install(path, quiet, version, platform)
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
  path <- Sys_getenv("VAULTR_TEST_SERVER_BIN_PATH", NULL)
  if (is.null(path)) {
    return(NULL)
  }
  if (!file.exists(path) || !is_directory(path)) {
    return(NULL)
  }
  bin <- file.path(path, vault_exe_filename())
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

    initialize = function(bin, port) {
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
      gc() # try and free up any previous cases
      ret <- free_port(self$port)
      self$port <- self$port + 1L
      ret
    },

    new_server = function(https = FALSE, init = TRUE,
                          if_disabled = testthat::skip) {
      if (!self$enabled) {
        if_disabled("vault is not enabled")
      } else {
        tryCatch(
          R6_vault_server_instance$new(self$bin, self$new_port(), https, init),
          error = function(e)
            testthat::skip(paste("vault server failed to start:",
                                 e$message)))
      }
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
      stop("vault has died:\n", err)
    }
    message("...waiting for Vault to start")
    Sys.sleep(poll)
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

  cl <- vault_client(addr = addr)
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
  cacert <- file.path(config_path, "server-cert.pem")
  cl <- vault_client(addr = addr, tls_config = cacert)

  ## Here, our test function is a bit different because we're not
  ## expecting the server to be *initialised*, just to be ready to
  ## accept connections
  vault_server_wait(function() !cl$operator$is_initialized(), process)

  if (init) {
    res <- cl$operator$init(5, 3) # 5 / 3 key split
    keys <- res$keys_base64
    root_token <- res$root_token
    for (k in keys) {
      cl$operator$unseal(k)
    }
  } else {
    keys <- NULL
    root_token <- NULL
  }
  on.exit()

  list(process = process,
       addr = addr,
       token = root_token,
       keys = keys,
       cacert = cacert)
}


vault_platform <- function(sysname = Sys.info()[["sysname"]]) {
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

vault_exe_filename <- function(platform = vault_platform()) {
  if (platform == 'windows') {
    "vault.exe"
  } else {
    "vault"
  }
}


vault_install <- function(dest, quiet, version, platform = vault_platform()) {
  dest_bin <- file.path(dest, vault_exe_filename(platform))
  if (!file.exists(dest_bin)) {
    message(sprintf("installing vault to '%s'", dest))
    url <- vault_url(version, platform)
    zip <- download_file(url, quiet = quiet)
    tmp <- tempfile()
    dir_create(tmp)
    utils::unzip(zip, exdir = tmp)
    file_copy(file.path(tmp, vault_exe_filename(platform)), dest_bin)
    unlink(tmp, recursive = TRUE)
    file.remove(zip)
    Sys.chmod(dest_bin, "755")
  }
  invisible(dest_bin)
}
