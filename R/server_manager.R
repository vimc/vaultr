##' Control a server for use with testing.  This is designed to be
##' used only by other packages that wish to run tests against a vault
##' server.  You will need to set `VAULTR_TEST_SERVER_BIN_PATH` to
##' point at the directory containing the vault binary, to the binary
##' itself, or to the value `auto` to try and find it on your `PATH`.
##'
##' Once created with `vault_test_server`, a server will stay
##' alive for as long as the R process is alive *or* until the
##' `vault_server_instance` object goes out of scope and is
##' garbage collected.  Calling `$kill()` will explicitly stop
##' the server, but this is not strictly needed.  See below for
##' methods to control the server instance.
##'
##' @section Warning:
##'
##' Starting a server in test mode must *not* be used for production
##'   under any circumstances.  As the name suggests,
##'   `vault_test_server` is a server suitable for *tests* only and
##'   lacks any of the features required to make vault secure.  For
##'   more information, please see the the official Vault
##'   documentation on development servers:
##'   https://developer.hashicorp.com/vault/docs/concepts/dev-server
##'
##' @title Control a test vault server
##'
##' @param https Logical scalar, indicating if a https-using server
##'   should be created, rather than the default vault dev-mode
##'   server.  This is still *entirely* insecure, and uses self
##'   signed certificates that are bundled with the package.
##'
##' @param init Logical scalar, indicating if the https-using server
##'   should be initialised.
##'
##' @param if_disabled Callback function to run if the vault server is
##'   not enabled.  The default, designed to be used within tests, is
##'   `testthat::skip`.  Alternatively, inspect the
##'   `$enabled` property of the returned object.
##'
##' @param quiet Logical, indicating if startup should be quiet and
##'   not print messages
##'
##' @export
##' @rdname vault_test_server
##' @aliases vault_server_instance
##' @examples
##'
##' # Try and start a server; if one is not enabled (see details
##' # above) then this will return NULL
##' server <- vault_test_server(if_disabled = message)
##'
##' if (!is.null(server)) {
##'   # We now have a server running on an arbitrary high port - note
##'   # that we are running over http and in dev mode: this is not at
##'   # all suitable for production use, just for tests
##'   server$addr
##'
##'   # Create clients using the client method - by default these are
##'   # automatically authenticated against the server
##'   client <- server$client()
##'   client$write("/secret/password", list(value = "s3cret!"))
##'   client$read("/secret/password")
##'
##'   # The server stops automatically when the server object is
##'   # garbage collected, or it can be turned off with the
##'   # 'kill' method:
##'   server$kill()
##'   tryCatch(client$status(), error = function(e) message(e$message))
##' }
vault_test_server <- function(https = FALSE, init = TRUE,
                              if_disabled = testthat::skip,
                              quiet = FALSE) {
  global_vault_server_manager()$new_server(https, init, if_disabled, quiet)
}


global_vault_server_manager <- function() {
  if (is.null(vault_env$server_manager)) {
    bin <- vault_server_manager_bin()
    port <- vault_server_manager_port()
    vault_env$server_manager <- vault_server_manager$new(bin, port)
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
  if (identical(path, "auto")) {
    path <- unname(Sys.which("vault"))
    if (!nzchar(path)) {
      return(NULL)
    }
  }
  if (!file.exists(path)) {
    return(NULL)
  }
  if (is_directory(path)) {
    bin <- file.path(path, vault_exe_filename())
  } else {
    bin <- path
  }
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


vault_server_manager <- R6::R6Class(
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
                          if_disabled = testthat::skip,
                          quiet = FALSE) {
      if (!self$enabled) {
        if_disabled("vault is not enabled")
      } else {
        tryCatch(
          vault_server_instance$new(self$bin, self$new_port(), https, init,
                                    quiet),
          error = function(e) {
            testthat::skip(paste("vault server failed to start:",
                                 e$message))
          })
      }
    }
  ))


fake_token <- function() {
  data <- sample(c(0:9, letters[1:6]), 32, TRUE)
  n <- c(8, 4, 4, 4, 12)
  paste(vcapply(split(data, rep(seq_along(n), n)), paste0, collapse = "",
                USE.NAMES = FALSE), collapse = "-")
}


vault_server_wait <- function(test, process, timeout = 5, poll = 0.05,
                              quiet = FALSE) {
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
    message_quietly("...waiting for Vault to start", quiet = quiet)
    Sys.sleep(poll)
  }
}


vault_server_start_dev <- function(bin, port, quiet) {
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
  vault_server_wait(cl$operator$is_initialized, process, quiet = quiet)
  on.exit()

  for (i in 1:5) {
    txt <- readLines(process$get_output_file())
    re <- "\\s*Unseal Key:\\s+([^ ]+)\\s*$"
    i <- grep(re, txt)
    key <- NULL
    if (length(i) == 1L) {
      key <- sub(re, "\\1", txt[[i]])
      break
    }
    Sys.sleep(0.5) # nocov
  }

  ## See https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2#setup
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


vault_server_start_https <- function(bin, port, init, quiet) {
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
  vault_server_wait(function() !cl$operator$is_initialized(), process,
                    quiet = quiet)

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

vault_exe_filename <- function(platform = vault_platform()) {
  if (platform == "windows") {
    "vault.exe"
  } else {
    "vault"
  }
}
