#!/usr/bin/env Rscript

VAULT_VERSION <- "0.7.3"

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

vault_install <- function(dest) {
  dest_bin <- file.path(dest, "vault")
  if (!file.exists(dest_bin)) {
    message(sprintf("installing vault to '%s'", dest))
    url <- vault_url(VAULT_VERSION)
    zip <- download_file(url)
    cat("\n")
    tmp <- tempfile()
    dir.create(tmp)
    unzip(zip, exdir = tmp)
    ok <- file.copy(file.path(tmp, "vault"), dest_bin)
    unlink(tmp, recursive = TRUE)
    file.remove(zip)
    Sys.chmod(dest_bin, "755")
  }
  invisible(dest_bin)
}

download_file <- function(url, path = tempfile()) {
  r <- httr::GET(url, httr::write_disk(path), httr::progress())
  httr::stop_for_status(r)
  path
}

main <- function(args = commandArgs(TRUE)) {
  if (length(args) != 1L) {
    stop("one argument required")
  }
  dest <- args[[1]]
  if (!isTRUE(file.info(dest)$isdir)) {
    stop("argument must be an existing directory")
  }
  vault_install(dest)
}

if (!interactive()) {
  main()
}
