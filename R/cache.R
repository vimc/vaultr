token_cache <- R6::R6Class(
  "token_cache",

  public = list(
    tokens = setNames(list(), character()),

    client_addr = function(api_client) {
      api_client$addr
    },

    set = function(api_client, token, use_cache = TRUE) {
      if (use_cache) {
        self$tokens[[self$client_addr(api_client)]] <- token
      }
    },

    get = function(api_client = NULL, use_cache = TRUE, quiet = TRUE) {
      if (!use_cache) {
        return(NULL)
      }
      addr <- self$client_addr(api_client)
      token <- self$tokens[[addr]]
      if (is.null(token)) {
        return(NULL)
      }
      if (!api_client$verify_token(token, quiet)$success) {
        self$tokens[[addr]] <- NULL
        return(NULL)
      }
      token
    },

    clear = function() {
      self$tokens <- setNames(list(), character())
    },

    list = function() {
      names(self$tokens)
    }
  ))
