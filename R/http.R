vault_request <- function(verb, url, verify, token, path, ...,
                          body = NULL, to_json = TRUE,
                          allow_missing_token = FALSE) {
  if (is.null(token) && !allow_missing_token) {
    stop("Have not authenticated against vault")
  }
  res <- verb(paste0(url, prepare_path(path)), verify, token,
              httr::accept_json(),
              body = body, encode = "json", ...)
  vault_client_response(res, to_json)
}


vault_client_response <- function(res, to_json = TRUE) {
  code <- httr::status_code(res)
  if (code >= 400 && code < 600) {
    if (response_is_json(res)) {
      dat <- response_to_json(res)
      ## TODO: this section is a bit out of sync with
      ## https://www.vaultproject.io/api/overview.html#error-response
      ## which mentions errors but not warnings
      errors <- list_to_character(dat$errors)
      warnings <- list_to_character(dat$warnings)
      text <- paste(c(errors, warnings), collapse = "\n")
    } else {
      errors <- NULL
      text <- trimws(httr::content(res, "text", encoding = "UTF-8"))
    }
    stop(vault_error(code, text, errors))
  }

  if (code == 204) {
    res <- NULL
  } else if (to_json) {
    res <- response_to_json(res)
  }
  res
}

vault_error <- function(code, text, errors) {
  if (!nzchar(text)) {
    text <- httr::http_status(code)$message
  }
  type <- switch(as.character(code),
                 "400" = "vault_invalid_request",
                 "401" = "vault_unauthorized",
                 "403" = "vault_forbidden",
                 "404" = "vault_invalid_path",
                 "429" = "vault_rate_limit_exceeded",
                 "500" = "vault_internal_server_error",
                 "501" = "vault_not_initialized",
                 "503" = "vault_down",
                 "vault_unknown_error")
  err <- list(code = code,
              errors = errors,
              message = text)
  class(err) <- c(type, "vault_error", "error", "condition")
  err
}
