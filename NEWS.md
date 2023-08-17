## 1.1.5

* Support for authentication with LDAP (#42)

## 1.1.2

* Support for vault [namespaces](https://developer.hashicorp.com/vault/tutorials/enterprise/namespaces) on enterprise versions of vault

## 1.0.4

* `vaultr::vault_resolve_secrets` (and `$read` in the kv1 secrets engine) provide more information about what was being read at the point of failure (VIMC-3437)

## 1.0.3

* New convenience argument to `vaultr::vault_resolve_secrets` to pass in all connection arguments at once, designed to make this easier to use from scripts (VIMC-3397).

## 1.0.2

* First public release

## 0.2.6

* All objects gain a `help()` method, with the aim of making the main help easier to find.

## 0.2.5

* Support for AppRole authentication
* Move secrets support under secrets top level element (so `vault$secrets$kv1` rather than `vault$kv1`); VIMC-2891

## 0.2.4

* Support for the [`cubbyhole`](https://www.vaultproject.io/docs/secrets/cubbyhole/index.html) secret engine and response wrapping
* Faster testing on windows due to improved timeouts while looking for free ports

## 0.2.3

* Fix windows filename issue with test server

## 0.2.2

* Add vault_resolve_secrets method

## 0.2.1

* Documentation for core classes

## 0.2.0

* Complete rewrite based on use over the last year:
  - supporting many more vault methods
  - a better base for ongoing method support
  - rationalised authentication and caching
  - easier to use server for tests

## 0.1.0

* Initial internal release
