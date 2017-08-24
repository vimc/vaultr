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
