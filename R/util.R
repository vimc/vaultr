response_to_json <- function(res) {
  jsonlite::fromJSON(httr::content(res, "text", encoding = "UTF-8"),
                     simplifyVector = FALSE)
}

`%||%` <- function(a, b) {
  if (is.null(a)) b else a
}

`%&&%` <- function(a, b) {
  if (is.null(a)) NULL else b
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

Sys_getenv <- function(name, unset = NULL, mode = "character") {
  value <- Sys.getenv(name, NA_character_)
  if (is.na(value)) {
    value <- unset
  } else if (mode == "integer") {
    if (!grepl("^-?[0-9]+$", value)) {
      stop(sprintf("Invalid input for integer '%s'", value))
    }
    value <- as.integer(value)
  } else if (mode != "character") {
    stop("Invalid value for 'mode'")
  }
  value
}

vault_arg <- function(x, name, mode = "character") {
  x %||% Sys_getenv(name, NULL, mode)
}

download_file <- function(url, path = tempfile(), quiet = FALSE) {
  r <- httr::GET(url, httr::write_disk(path), if (!quiet) httr::progress())
  httr::stop_for_status(r)
  path
}


drop_null <- function(x) {
  x[!vlapply(x, is.null)]
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
  getPass::getPass(prompt, TRUE)
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

string_starts_with <- function(x, sub) {
  substr(x, 1, nchar(sub)) == sub
}


is_directory <- function(path) {
  file.info(path, extra_cols = FALSE)$isdir
}


free_port <- function(port, max_tries = 10) {
  for (i in seq_len(max_tries)) {
    if (check_port(port)) {
      return(port)
    }
    port <- port + 1L
  }
  stop(sprintf("Did not find a free port between %d..%d",
               port - max_tries, port - 1),
       call. = FALSE)
}


check_port <- function(port) {
  con <- tryCatch(suppressWarnings(socketConnection(
    "localhost", port = port, timeout = 0.1, open = "r")),
    error = function(e) NULL)
  if (is.null(con)) {
    return(TRUE)
  }
  close(con)
  FALSE
}


pretty_sec <- function(n) {
  if (n < 60) { # less than a minute
    sprintf("%ds", n)
  } else if (n < 60 * 60) { # less than an hour
    sprintf("~%dm", round(n / 60))
  } else if (n < 60 * 60 * 24) { # less than a day
    sprintf("~%dh", round(n / 60 / 60))
  } else { # more than a day
    sprintf("~%dd", round(n / 60 / 60 / 24))
  }
}


pretty_lease <- function(lease) {
  sprintf("ok, duration: %s s (%s)", lease, pretty_sec(lease))
}


squote <- function(x) {
  sprintf("'%s'", x)
}


encode64 <- function(input) {
  jsonlite::base64_enc(input)
}


decode64 <- function(input) {
  jsonlite::base64_dec(input)
}
