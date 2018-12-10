vault_client_format <- function(object, brief, name, description) {
  if (brief) {
    return(description)
  }
  nms <- setdiff(ls(object), c("format", "clone", "initialize"))
  fns <- vlapply(nms, function(x) is.function(object[[x]]))
  is_obj <- vlapply(nms, function(x) inherits(object[[x]], "R6"))

  calls <- vcapply(nms[fns], function(x) capture_args(object[[x]], x),
                   USE.NAMES = FALSE)
  if (any(is_obj)) {
    objs <- c(
      "  Command groups:",
      vcapply(nms[is_obj], function(x)
        sprintf("    %s: %s", x, object[[x]]$format(TRUE)),
        USE.NAMES = FALSE))
  } else {
    objs <- NULL
  }

  c(sprintf("<vault: %s>", name),
    objs,
    "  Commands:",
    calls)
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
