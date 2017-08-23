assert_is <- function(x, what, name = deparse(substitute(x))) {
  if (!inherits(x, what)) {
    sprintf("Expected '%s' to be a %s", name, paste(what, collapse = " / "))
  }
}

assert_length <- function(x, len, name = deparse(substitute(x))) {
  if (length(x) != len) {
    sprintf("Expected '%s' to be length %d", name, len)
  }
}

assert_absolute_path <- function(path) {
  if (!is_absolute_path(path)) {
    stop("Expected an absolute path")
  }
}

assert_scalar <- function(x, name = deparse(substitute(x))) {
  if (length(x) != 1) {
    stop(sprintf("'%s' must be a scalar", name), call. = FALSE)
  }
}

assert_character <- function(x, name = deparse(substitute(x))) {
  if (!is.character(x)) {
    stop(sprintf("'%s' must be character", name), call. = FALSE)
  }
}

assert_scalar_character <- function(x, name = deparse(substitute(x))) {
  assert_scalar(x, name)
  assert_character(x, name)
}

assert_named <- function(x, name = deparse(substitute(x))) {
  if (is.null(names(x))) {
    stop(sprintf("'%s' must be named", name))
  }
}
