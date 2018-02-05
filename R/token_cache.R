##' Clear all cached token
##'
##' Vaultr stores tokens in two places - one session specific and one
##' persistent.  This function clears these out which might be useful
##' in debugging (otherwise pass in the \code{renew} argument to
##' \code{auth}).  It also comes in useful in testing packages that
##' depend on vaultr.
##'
##' @title Clear vaultr token cache
##'
##' @param session Logical, indicating if we should clear the session
##'   keys
##'
##' @param persistent Logical, indicating if we should clear the
##'   persistent keys
##'
##' @param cache_dir Location of persistent keys (otherwise uses the
##'   \code{VAULTR_CACHE_DIR} environment variable)
##'
##' @param quiet Logical, indicating if messages should be ommited
##'
##' @export
vault_clear_token_cache <- function(session = TRUE, persistent = TRUE,
                                    cache_dir = NULL, quiet = FALSE) {
  ## TODO: consider per-server deletion of tokens
  if (session) {
    tokens <- ls(vault_env$tokens, all.names = TRUE)
    if (length(tokens) > 0L) {
      if (!quiet) {
        message("Removing session tokens\n",
                paste(sprintf("  - %s", sort(tokens)), collapse = "\n"))
      }
      clear_env(vault_env$tokens)
    }
  }
  if (persistent) {
    cache_dir <- vault_arg(cache_dir, "VAULTR_CACHE_DIR")
    if (!is.null(cache_dir)) {
      tokens <- dir(cache_dir, all.files = TRUE, no.. = TRUE)
      if (!all(grepl("^https?_", tokens))) {
        stop(sprintf("Unexpected files in %s - not deleting", cache_dir))
      }
      if (length(tokens) > 0L) {
        if (!quiet) {
          message("Removing persistent tokens\n",
                  paste(sprintf("  - %s", sort(tokens)), collapse = "\n"))
        }
        unlink(cache_dir, recursive = TRUE)
      }
    }
  }
}

token_cache_get <- function(server, cache_dir, quiet) {
  if (server %in% names(vault_env$tokens)) {
    if (!quiet) {
      message("Using cached token from this session")
    }
    return(vault_env$tokens[[server]])
  }
  cache_path <- token_cache_path(server, cache_dir)
  if (!is.null(cache_path) && file.exists(cache_path) && !is.null(ssh_key())) {
    if (!quiet) {
      message("Using cached token from persistent cache ", cache_path)
    }
    token <- rawToChar(cyphr::decrypt_file(cache_path, ssh_key()))
    vault_env$tokens[[server]] <- token
    return(token)
  }
  NULL
}

token_cache_set <- function(server, token, cache_dir, quiet) {
  if (!(server %in% names(vault_env$tokens))) {
    if (!quiet) {
      message("Saving cached token for this session")
    }
    vault_env$tokens[[server]] <- token
  }
  cache_path <- token_cache_path(server, cache_dir)
  if (!is.null(cache_path) && !file.exists(cache_path) && !is.null(ssh_key())) {
    if (!quiet) {
      message("Saving cached token to persistent cache ", cache_path)
    }
    dir.create(dirname(cache_path), FALSE, TRUE)
    cyphr::encrypt_string(token, ssh_key(), cache_path)
  }
}

token_client_del <- function(server, cache_dir, quiet) {
  if (server %in% names(vault_env$tokens)) {
    if (!quiet) {
      message("Removing cached token from this session")
    }
    rm(list = server, envir = vault_env$tokens)
  }
  cache_path <- token_cache_path(server, cache_dir)
  if (!is.null(cache_path) && file.exists(cache_path)) {
    if (!quiet) {
      message("Removing cached token from persistent cache ", cache_path)
    }
    file.remove(cache_path)
  }
}

token_cache_path <- function(server, cache_dir) {
  cache_dir <- vault_arg(cache_dir, "VAULTR_CACHE_DIR")
  if (!(is.null(cache_dir) || isFALSE(cache_dir))) {
    file.path(cache_dir, mangle_url(server))
  } else {
    NULL
  }
}

ssh_key <- function(private = TRUE) {
  if (is.null(vault_env$ssh_key)) {
    vault_env$ssh_key <- tryCatch(error = function(e) NULL, {
      loadNamespace("cyphr")
      cyphr::keypair_openssl(NULL, NULL)
    })
  }
  vault_env$ssh_key
}

mangle_url <- function(server) {
  gsub("(://|/|:)", "_", server)
}
