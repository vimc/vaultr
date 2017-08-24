# vaultr

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip)

API client for [vault](https://www.vaultproject.io/)

## Usage

Currently this package does not wrap the whole vault API, which is fairly extensive.  Instead it mostly maps the bits that we need for VIMC (including the sections that I needed to create a set of tests).  It should be fairly straightforward to add more, and I welcome contributions.

The main use case we have is

* auth using github
* read secrets using the generic backend

For the first part, ensure that the environment variables are set

```
VAULT_ADDR=https://<vault-address>:8200
VAULT_AUTH_GITHUB_TOKEN=<your token>
```

Tokens can be generated [here](https://github.com/settings/tokens/new) (see the [tokens page](https://github.com/settings/tokens/) for more information) and must have the **user** scope.

Then run

```
cl <- vaultr:::vault_client_generic("github")
# Authenticating using github...ok, duration: 2764800 s (~32d)
```

which will fetch a token via the github authentication.  From this point you can then list secrets like

```
cl$list("/secret")
# [1] "/secret/foo"  "/secret/bar/"
```

and read secrets with

```
cl$read("/secret/foo")
# $password
# [1] "ru5wig2iengohcohya5uj0Hairahm5Muengu4NiaThee7quiku"
cl$read("/secret/foo", "password")
# [1] "ru5wig2iengohcohya5uj0Hairahm5Muengu4NiaThee7quiku"
```

or set secrets with

```
cl$write("/secret/foo", list(password = "my new password"))
```

or delete secrets with

```
cl$delete("/secret/foo")
```

## Installation

Install our current version via

```r
# install.packages("drat") # (if needed)
drat:::add("vimc")
install.packages("vaultr")
```

or install the bleeding edge with

```r
# install.packages("devtools") # (if needed)
devtools::install_gitub("vimc/vaultr")
```

## License

MIT © Imperial College of Science, Technology and Medicine
