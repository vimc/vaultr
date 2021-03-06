assert_is <- function(x, what, name = deparse(substitute(x))) {
  if (!inherits(x, what)) {
    stop(sprintf("'%s' must be a %s",
                 name, paste(what, collapse = " / ")))
  }
  invisible(x)
}


assert_length <- function(x, len, name = deparse(substitute(x))) {
  if (length(x) != len) {
    stop(sprintf("'%s' must have length %d", name, len))
  }
  invisible(x)
}


assert_scalar <- function(x, name = deparse(substitute(x))) {
  if (length(x) != 1) {
    stop(sprintf("'%s' must be a scalar", name), call. = FALSE)
  }
  invisible(x)
}


assert_character <- function(x, name = deparse(substitute(x))) {
  if (!is.character(x)) {
    stop(sprintf("'%s' must be a character", name), call. = FALSE)
  }
  invisible(x)
}

assert_integer <- function(x, strict = FALSE, name = deparse(substitute(x)),
                           what = "integer") {
  if (!(is.integer(x))) {
    usable_as_integer <-
      !strict && is.numeric(x) && (max(abs(round(x) - x)) < 1e-8)
    if (!usable_as_integer) {
      stop(sprintf("'%s' must be %s", name, what), call. = FALSE)
    }
  }
  invisible(x)
}


assert_logical <- function(x, name = deparse(substitute(x))) {
  if (!is.logical(x)) {
    stop(sprintf("'%s' must be a logical", name), call. = FALSE)
  }
  invisible(x)
}


assert_named <- function(x, name = deparse(substitute(x))) {
  if (is.null(names(x)) && length(x) > 0L) {
    stop(sprintf("'%s' must be named", name))
  }
  invisible(x)
}


assert_scalar_character <- function(x, name = deparse(substitute(x))) {
  assert_scalar(x, name)
  assert_character(x, name)
}


assert_scalar_integer <- function(x, strict = FALSE,
                                  name = deparse(substitute(x))) {
  assert_scalar(x, name)
  assert_integer(x, strict, name)
}


assert_scalar_logical <- function(x, name = deparse(substitute(x))) {
  assert_scalar(x, name)
  assert_logical(x, name)
}


assert_scalar_logical_or_null <- function(x, name = deparse(substitute(x))) {
  if (!is.null(x)) {
    assert_scalar_logical(x, name)
  }
  invisible(x)
}


assert_scalar_character_or_null <- function(x, name = deparse(substitute(x))) {
  if (!is.null(x)) {
    assert_scalar_character(x, name)
  }
  invisible(x)
}


assert_absolute_path <- function(path) {
  if (!is_absolute_path(path)) {
    stop("Expected an absolute path")
  }
  invisible(path)
}


assert_file_exists <- function(path, name = deparse(substitute(path))) {
  assert_scalar_character(path, name)
  if (!file.exists(path)) {
    stop(sprintf("The path '%s' does not exist (for '%s')", path, name),
         call. = FALSE)
  }
}


assert_is_duration <- function(x, name = deparse(substitute(x))) {
  assert_scalar_character(x)
  if (!grepl("^[0-9]+h$", x)) {
    stop(sprintf("'%s' is not a valid time duration for '%s'", x, name),
         call. = FALSE)
  }
  invisible(x)
}


assert_vault_version <- function(required, api_client, api, description) {
  have <- api_client$server_version()
  if (required > have) {
    stop(vault_invalid_version(required, have, api, description))
  }
}


vault_invalid_version <- function(required, server_version, api, description) {
  str <- sprintf("%s (%s) requires vault version >= %s but server is %s",
                 description, api, required, server_version)
  err <- list(message = str)
  class(err) <- c("vault_invalid_version",
                  "vault_error", "error", "condition")
  err
}


match_value <- function(arg, choices, name = deparse(substitute(arg))) {
  assert_scalar_character(arg)
  if (!(arg %in% choices)) {
    stop(sprintf("%s must be one of %s",
                 name, paste(squote(choices), collapse = ", ")))
  }
  arg
}
