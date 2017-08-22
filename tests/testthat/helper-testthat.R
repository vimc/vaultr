## To do the testing we're going to have to set up a test server.
## There is a docker vault dev image, and there's similar things that
## we can do on travis.  Consider basing off
## https://github.com/ianunruh/hvac perhaps.

server_manager <- R6::R6Class(
  "server_manager",

  public = list(
    config_path = NULL,
    client = NULL,

    keys = NULL,
    root_token = NULL,

    process = NULL,

    initialize = function(config_path, client) {
      self$config_path <- config_path
      self$client <- client
    },
    start = function() {
      message("starting server")
      args <- c("server", paste0("-config=", config_path))
      self$process <-
        processx::process$new(vault, args, stdout = "|", stderr = "|")

      for (i in 1:20) {
        res <- try(self$client$sys_initialized(), silent = TRUE)
        if (!inherits(res, "try-error")) {
          return(TRUE)
        }
        message("...waiting for Vault to start")
        Sys.sleep(0.5)
      }
      stop("Unable to start vault")
    },
    sys_initialize = function() {
      if (self$client$sys_is_initialized()) {
        stop("server is already initialized")
      }
      message("initialising server")
      result <- self$client$sys_initialize()
      self$root_token <- result[["root_token"]]
      self$keys <- result[["keys"]]
    },
    unseal = function() {
      self$client$unseal_multi(self$keys)
    }
  ))
