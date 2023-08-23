##' Vault client for secrets and sensitive data; this package provides
##' wrappers for HashiCorp's [vault server](https://vaultproject.io).
##' The package wraps most of the high-level API, and includes support
##' for authentication via a number of backends (tokens, username and
##' password, github, and "AppRole"), as well as a number of secrets
##' engines (two key-value stores, vault's cubbyhole and the transit
##' backend for encryption-as-a-service).
##'
##' To get started, you might want to start with the "vaultr"
##' vignette, available from the package with `vignette("vaultr")`.
##'
##' The basic design of the package is that it has very few
##' entrypoints - for most uses one will interact almost entirely with
##' the [vaultr::vault_client] function.  That function returns an
##' R6 object with several methods (functions) but also several
##' objects that themselves contain more methods and objects, creating
##' a nested tree of functionality.
##'
##' From any object, online help is available via the help method, for
##' example
##'
##' ```
##' client <- vaultr::vault_client()
##' client$secrets$transit$help()
##' ```
##'
##' For testing packages that rely on vault, there is support for
##' creating temporary vault servers; see `vaultr::vault_test_server`
##' and the "packages" vignette.
##'
##' @title Vault Client for Secrets and Sensitive Data
"_PACKAGE"
