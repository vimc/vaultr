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

Sys_getenv <- function(name, unset = NULL, mode = "character", error = FALSE) {
  value <- Sys.getenv(name, NA_character_)
  if (is.na(value)) {
    if (error) {
      stop(sprintf("Environment variable '%s' was not set", name),
           call. = FALSE)
    }
    value <- unset
  } else if (mode == "integer") {
    if (!grepl("^-?[0-9]+$", value)) {
      stop(sprintf("Invalid input for integer '%s'", value))
    }
    value <- as.integer(value)
  } else if (mode != "character") {
    stop("invalid value for 'mode'")
  }
  value
}

vault_arg <- function(x, name, mode = "character") {
  x %||% Sys_getenv(name, NULL, mode)
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


sprintfn <- function(fmt, args) {
  switch(as.character(length(args)),
         "0" = fmt,
         "1" = sprintf(fmt, args),
         "2" = sprintf(fmt, args[[1]], args[[2]]),
         stop("Not implemented [stevedore bug]"))
}


capture_args <- function(f, name, indent = 4, width = getOption("width"),
                         exdent = 4L) {
  args <- formals(f)

  if (length(args) == 0L) {
    return(sprintf("%s%s()", strrep(" ", indent), name))
  }

  args_default <- vcapply(args, deparse)
  args_str <- sprintf("%s = %s", names(args), args_default)
  args_str[!nzchar(args_default)] <- names(args)[!nzchar(args_default)]
  args_str[[1]] <- sprintf("%s(%s", name, args_str[[1]])
  args_str[[length(args)]] <- paste0(args_str[[length(args)]], ")")

  w <- width - indent - 2L
  ret <- character()
  s <- ""

  for (i in args_str) {
    ns <- nchar(s)
    ni <- nchar(i)
    if (ns == 0) {
      s <- paste0(strrep(" ", indent + if (length(ret) > 0L) exdent else 0L), i)
    } else if (ns + ni + 2 < w) {
      s <- paste(s, i, sep = ", ")
    } else {
      ret <- c(ret, paste0(s, ","))
      s <- paste0(strrep(" ", indent + exdent), i)
    }
  }

  ret <- c(ret, s)

  paste0(trimws(ret, "right"), collapse = "\n")
}


read_password <- function(prompt) {
  getPass::getPass(prompt, TRUE) # nocov
}


prepare_path <- function(path) {
  assert_scalar_character(path)
  if (!is_absolute_path(path)) {
    path <- paste0("/", path)
  }
  path
}


rand_str <- function(n) {
  paste0(sample(letters, n, TRUE), collapse = "")
}
