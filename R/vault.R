vault_addr <- function(addr) {
  addr <- addr %||%
    getOption("vault.addr",
              Sys.getenv("VAULT_ADDR", NA_character_))
  if (!is.character(addr) || length(addr) != 1L) {
    stop("invalid input for vault addr")
  }
  if (is.na(addr)) {
    stop("vault address not found")
  }
  if (!grepl("^https://.+", addr)) {
    stop("Expected an https url for vault addr")
  }
  addr
}
