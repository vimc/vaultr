#!/usr/bin/env Rscript

main <- function(args = commandArgs(TRUE)) {
  if (length(args) != 1L) {
    stop("one argument required")
  }
  dest <- args[[1]]
  vaultr::vault_test_server_install(dest)
}

if (!interactive()) {
  main()
}
