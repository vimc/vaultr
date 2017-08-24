vault_GET <- function(url, verify, token, path, ..., to_json = TRUE) {
  url <- paste0(url, path)
  res <- httr::GET(url, verify, token, httr::accept_json(), ...)
  vault_client_response(res, to_json)
}

vault_PUT <- function(url, verify, token, path, body = NULL, ...,
                      to_json = TRUE) {
  url <- paste0(url, path)
  res <- httr::PUT(url, verify, token, httr::accept_json(),
                   body = body, encode = "json", ...)
  vault_client_response(res, to_json)
}

vault_POST <- function(url, verify, token, path, body = NULL, ...,
                       to_json = TRUE) {
  url <- paste0(url, path)
  res <- httr::POST(url, verify, token, httr::accept_json(),
                    body = body, encode = "json", ...)
  vault_client_response(res, to_json)
}

vault_DELETE <- function(url, verify, token, path, ..., to_json = TRUE) {
  url <- paste0(url, path)
  res <- httr::DELETE(url, verify, token, httr::accept_json(), ...)
  vault_client_response(res, to_json)
}

vault_client_response <- function(res, to_json = TRUE) {
  code <- httr::status_code(res)
  if (code >= 400 && code < 600) {
    if (response_is_json(res)) {
      errors <- response_to_json(res)$errors
      text <- paste(errors, collapse = "\n")
    } else {
      errors <- NULL
      text <- trimws(httr::content(res, "text", encoding = "UTF-8"))
    }
    stop(vault_error(code, text, errors))
  }
  if (to_json) {
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
