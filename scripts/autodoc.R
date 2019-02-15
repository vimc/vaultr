#!/usr/bin/env Rscript

devtools::load_all(".")

add_usage <- function(dat, cl) {
  capture_usage <- function(name) {
    tmp <- capture.output(args(cl$public_methods[[name]]))
    tmp <- strip_trailing_whitespace(paste(tmp[-length(tmp)], collapse = "\n"))
    sub("^function\\s*", name, tmp)
  }

  valid_fields <- names(cl$public_fields)
  valid_active <- names(cl$active)
  valid_methods <- names(cl$public_methods)

  valid <- c(valid_fields, valid_active, valid_methods)
  extra <- setdiff(names(dat), valid)
  if (length(extra) > 0L) {
    warning(sprintf("In '%s' extra methods: %s",
                    cl$classname,
                    paste(extra, collapse = ", ")),
            immediate. = TRUE, call. = FALSE)
  }

  for (name in names(dat)) {
    dat[[name]]$method_name <- name
    if (name %in% valid_methods) {
      dat[[name]]$usage <- capture_usage(name)
      dat[[name]]$order <- names(formals(cl$public_methods[[name]]))
    }
  }
  dat
}


indent <- function(str, n, pad = NULL) {
  if (is.null(pad)) {
    pad <- paste(rep(" ", n), collapse = "")
  }
  p <- function(s) {
    paste(paste0(pad, s), collapse = "\n")
  }
  vapply(strsplit(str, "\n"), p, character(1))
}


format_params <- function(xp) {
  fmt1 <- "\\itemize{\n%s\n}"
  fmt2 <- "\\item{\\code{%s}: %s\n}\n"
  pars <- sprintf(fmt2, names(xp), indent(unlist(xp), 2))
  sprintf(fmt1, indent(paste(pars, collapse = "\n"), 2))
}


format_method <- function(x) {
  title <- sprintf("\\item{\\code{%s}}{", x$method_name)
  end <- "}"

  p_msg   <- setdiff(x$order, names(x$params))
  p_extra <- setdiff(names(x$params), x$order)
  if (length(p_msg) > 0) {
    warning(sprintf("In '%s', missing parameters: %s",
                    x$method_name, paste(p_msg, collapse = ", ")),
            immediate. = TRUE, call. = FALSE)
  }
  if (length(p_extra) > 0) {
    warning(sprintf("In '%s', extra parameters: %s",
                    x$method_name, paste(p_extra, collapse = ", ")),
            immediate. = TRUE, call. = FALSE)
  }
  ## preseve order, though I'm pretty sure that the yaml package is
  ## actually preserving it.
  if (length(p_msg) == 0 && length(p_extra) == 0) {
    x$params <- x$params[x$order]
  }

  body <- x$short
  if (!is.null(x$usage)) {
    body <- paste0(body, sprintf("\n\n\\emph{Usage:}\\code{%s}", x$usage))
  }
  if (!is.null(x$params)) {
    body <- paste0(body, "\n\n\\emph{Arguments:}\n", format_params(x$params))
  }
  if (!is.null(x$details)) {
    body <- paste0(body, "\n\n\\emph{Details:}\n", x$details)
  }
  if (!is.null(x$value)) {
    body <- paste0(body, "\n\n\\emph{Value}:\n", x$value)
  }
  paste(title, indent(body, 2), end, sep = "\n")
}


strip_trailing_whitespace <- function(x) {
  gsub("[ \t]+(\n|$)", "\\1", x)
}


format_class <- function(x) {
  ret <- vapply(x, format_method, character(1))
  ret <- sprintf("@section Methods:\n\n\\describe{\n%s\n}",
                 paste(ret, collapse = "\n"))
  ret <- indent(ret, pad = "##' ")
  strip_trailing_whitespace(ret)
}


yaml_load <- function(string) {
  handlers <- list(`bool#yes` = function(x) {
    if (identical(toupper(x), "TRUE")) TRUE else x
  }, `bool#no` = function(x) {
    if (identical(toupper(x), "FALSE")) FALSE else x
  })
  yaml::yaml.load(string, handlers = handlers)
}


yaml_read <- function(filename) {
  yaml_load(paste(readLines(filename), collapse = "\n"))
}


process <- function(path, class) {
  dat <- yaml_read(path)
  str <- format_class(add_usage(dat, class))
  dest <- sub("\\.yml", ".R", path)
  message("writing ", dest)
  writeLines(str, dest)
}


process_all <- function() {
  process("man-roxygen/vault_api_client.yml", R6_vault_api_client)

  process("man-roxygen/vault_client.yml", R6_vault_client)
  process("man-roxygen/vault_client_audit.yml", R6_vault_client_audit)
  process("man-roxygen/vault_client_auth.yml", R6_vault_client_auth)
  process("man-roxygen/vault_client_auth_github.yml",
          R6_vault_client_auth_github)
  process("man-roxygen/vault_client_auth_userpass.yml",
          R6_vault_client_auth_userpass)
  process("man-roxygen/vault_client_kv1.yml", R6_vault_client_kv1)
  process("man-roxygen/vault_client_kv2.yml", R6_vault_client_kv2)
  process("man-roxygen/vault_client_operator.yml", R6_vault_client_operator)
  process("man-roxygen/vault_client_policy.yml", R6_vault_client_policy)
  process("man-roxygen/vault_client_secrets.yml", R6_vault_client_secrets)
  process("man-roxygen/vault_client_token.yml", R6_vault_client_token)
  process("man-roxygen/vault_client_tools.yml", R6_vault_client_tools)
  process("man-roxygen/vault_client_transit.yml", R6_vault_client_transit)

  process("man-roxygen/vault_server_instance.yml", R6_vault_server_instance)
}


if (!interactive()) {
  process_all()
}
