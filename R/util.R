response_to_json <- function(res) {
  jsonlite::fromJSON(httr::content(res, "text", encoding = "UTF-8"),
                     simplifyVector = FALSE)
}

`%||%` <- function(a, b) {
  if (is.null(a)) b else a
}

list_to_character <- function(x) {
  vapply(x, identity, character(1))
}

response_is_json <- function(x) {
  content_type <- httr::headers(x)[["Content-Type"]]
  dat <- httr::parse_media(content_type)
  dat$type == "application" && dat$subtype == "json"
}

is_absolute_path <- function(path) {
  substr(path, 1, 1) == "/"
}

vlapply <- function(X, FUN, ...) {
  vapply(X, FUN, logical(1), ...)
}
vcapply <- function(X, FUN, ...) {
  vapply(X, FUN, character(1), ...)
}

data_frame <- function(...) {
  data.frame(..., stringsAsFactors = FALSE)
}

strsub <- function(str, tr) {
  assert_character(tr)
  assert_named(tr)
  from <- names(tr)
  to <- unname(tr)
  for (i in seq_along(from)) {
    str <- gsub(from[[i]], to[[i]], str, fixed = TRUE)
  }
  str
}

Sys_getenv <- function(var, unset = NULL, as = "character") {
  value <- Sys.getenv(var, NA_character_)
  if (is.na(value)) {
    value <- unset
  } else if (as == "integer") {
    if (!grepl("^-?[0-9]+$", value)) {
      stop(sprintf("Invalid input for integer '%s'", value))
    }
    value <- as.integer(value)
  } else if (as != "character") {
    stop("invalid value for 'as'")
  }
  value
}

vault_arg <- function(x, var, as = "character") {
  x %||% Sys_getenv(var, NULL, as)
}

download_file <- function(url, path = tempfile(), quiet = FALSE) {
  r <- httr::GET(url, httr::write_disk(path), if (!quiet) httr::progress())
  if (!quiet) {
    cat("\n")
  }
  httr::stop_for_status(r)
  path
}

isFALSE <- function(x) {
  identical(as.vector(x), FALSE)
}

clear_env <- function(env) {
  rm(list = ls(env, all.names = TRUE), envir = env)
}


drop_null <- function(x) {
  x[!vlapply(x, is.null)]
}
