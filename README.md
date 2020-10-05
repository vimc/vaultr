# vaultr

<!-- badges: start -->
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Travis-CI Build Status](https://travis-ci.org/vimc/vaultr.svg?branch=master)](https://travis-ci.org/vimc/vaultr)
[![AppVeyor build status](https://ci.appveyor.com/api/projects/status/github/vimc/vaultr?branch=master&svg=true)](https://ci.appveyor.com/project/richfitz/vaultr)
[![codecov.io](https://codecov.io/github/vimc/vaultr/coverage.svg?branch=master)](https://codecov.io/github/vimc/vaultr?branch=master)
[![](http://www.r-pkg.org/badges/version/vaultr)](https://cran.r-project.org/package=vaultr)
<!-- badges: end -->

API client for [vault](https://www.vaultproject.io/).

Vault provides a platform for distributing secrets across machines.  This package wraps the [vault http API](https://www.vaultproject.io/api/index.html) to allow secrets to be accessed from R.  Secrets might be passwords, tokens, certificates or any other sensitive data.

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
# install.packages("drat") # (if needed)
drat:::add("vimc")
install.packages("vaultr")
```

or install the bleeding edge with

```r
# install.packages("devtools") # (if needed)
devtools::install_github("vimc/vaultr", upgrade = FALSE)
```

## License

MIT © Imperial College of Science, Technology and Medicine
