assert_is <- function(x, what, name = deparse(substitute(x))) {
  if (!inherits(x, what)) {
    stop(sprintf("'%s' must be a %s",
                 name, paste(what, collapse = " / ")))
  }
}

assert_length <- function(x, len, name = deparse(substitute(x))) {
  if (length(x) != len) {
    stop(sprintf("'%s' must have length %d", name, len))
  }
}

assert_scalar <- function(x, name = deparse(substitute(x))) {
  if (length(x) != 1) {
    stop(sprintf("'%s' must be a scalar", name), call. = FALSE)
  }
}

assert_character <- function(x, name = deparse(substitute(x))) {
  if (!is.character(x)) {
    stop(sprintf("'%s' must be a character", name), call. = FALSE)
  }
}

assert_named <- function(x, name = deparse(substitute(x))) {
  if (is.null(names(x))) {
    stop(sprintf("'%s' must be named", name))
  }
}

assert_scalar_character <- function(x, name = deparse(substitute(x))) {
  assert_scalar(x, name)
  assert_character(x, name)
}

assert_absolute_path <- function(path) {
  if (!is_absolute_path(path)) {
    stop("Expected an absolute path")
  }
}

assert_path_prefix <- function(path, starts_with) {
  assert_scalar_character(path)
  if (!identical(substr(path, 1L, nchar(starts_with)), starts_with)) {
    stop(sprintf("Expected path to start with '%s'", starts_with))
  }
}
