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
    file.path(cache_dir, base64url::base64_urlencode(server))
  } else {
    NULL
  }
}

ssh_key <- function(private = TRUE) {
  if (!requireNamespace("cyphr", quietly = TRUE)) {
    return(NULL)
  }
  if (is.null(vault_env$ssh_key)) {
    vault_env$ssh_key <- tryCatch(cyphr::keypair_openssl(NULL, NULL),
                                  error = function(e) NULL)
  }
  vault_env$ssh_key
}
