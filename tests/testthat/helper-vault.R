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
      vault <- Sys.which("vault")
      if (!nzchar(vault)) {
        stop("vault executable not found")
      }
      message("starting server")
      args <- c("server", paste0("-config=", self$config_path))
      self$process <-
        processx::process$new(vault, args, stdout = "|", stderr = "|")

      for (i in 1:20) {
        res <- try(self$client$sys_is_initialized(), silent = TRUE)
        if (!inherits(res, "try-error")) {
          return(TRUE)
        }
        if (!self$process$is_alive()) {
          err <- paste(self$process$read_all_output_lines(), collapse = "\n")
          stop("vault has died: ", err)
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
    },
    kill = function() {
      self$process$kill()
    }
  ))

test_client <- function(...) {
  vault_client$new(verify = "server/server-cert.pem")
}

server <- NULL
server_start <- function() {
  server <<- server_manager$new("server", test_client())
  server$start()
  server$sys_initialize()
  server$unseal()
  invisible()
}

server_teardown <- function() {
  if (server$process$is_alive()) {
    server$process$kill()
  }
}
