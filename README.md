# vaultr

<!-- badges: start -->
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![R-CMD-check](https://github.com/vimc/vaultr/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/vimc/vaultr/actions/workflows/R-CMD-check.yaml)
[![codecov.io](https://codecov.io/github/vimc/vaultr/coverage.svg?branch=master)](https://app.codecov.io/github/vimc/vaultr?branch=master)
[![CodeFactor](https://www.codefactor.io/repository/github/vimc/vaultr/badge)](https://www.codefactor.io/repository/github/vimc/vaultr)
[![](http://www.r-pkg.org/badges/version/vaultr)](https://cran.r-project.org/package=vaultr)
<!-- badges: end -->

Interact with [HashiCorp's vault](https://www.vaultproject.io/), to securely use secrets from R.  This package wraps the [vault http API](https://www.vaultproject.io/api/index.html) to allow secrets to be accessed from R.  Secrets might be passwords, tokens, certificates or any other sensitive data.

* Authenticate with several different providers (token, username and password, GitHub, LDAP, and "approle")
* Read and write secrets into vault using its key-value stores (version 1 or 2), cubbyhole and in-transit "encryption-as-a-service"
* Inspect and work with vault tokens
* Read, write and update vault policies
* Allows a degree of access to operator maintenance
* Work with vault's audit devices

## Usage



Create a vault client with the `vault_client` function:


```r
vault <- vaultr::vault_client(login = TRUE)
```

```
## Verifying token
```

Interact with vault using this object:


```r
vault$list("secret/database")
```

```
## [1] "admin"    "readonly"
```

and read secrets with


```r
vault$read("secret/database/admin")
```

```
## $value
## [1] "s3cret"
```


```r
vault$read("secret/database/readonly", field = "value")
```

```
## [1] "passw0rd"
```

or set secrets with

```r
vault$write("secret/webserver", list(password = "horsestaple"))
vault$read("secret/webserver")
```

or delete secrets with

```r
vault$delete("/secret/database/readonly")
```

## Installation

Install `vaultr` from CRAN with

```r
install.packages("vaultr")
```

To install our internally released version (which might be ahead of CRAN) via drat, use


```r
install.packages(
  "vaultr",
  repos = c("https://vimc.r-universe.dev", "https://cloud.r-project.org"))
```

or install the bleeding edge with

```r
remotes::install_gitub("vimc/vaultr", upgrade = FALSE)
```

## License

MIT © Imperial College of Science, Technology and Medicine
