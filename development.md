# Development notes

This file contains (hopefully) useful information for developing `vaultr`.

## Running all the tests

Set three environment variables before loading the package:

```
VAULTR_TEST_SERVER_PORT=18200
VAULTR_TEST_SERVER_BIN_PATH=/usr/bin  (or "C:/Program Files/Vault/")
NOT_CRAN=true
```

With these set, and the package loaded with `pkgload::load_all()` you should now be able to run

```r
srv <- vault_test_server()
```

to bring up a test server.

## Configuring LDAP

This is quite fiddly and worth checking that it works with the vault dev server before getting too involved with the R client.

Start the server with

```
vault server -dev -dev-root-token-id=MlF2MrMpmwfCZOkCHoZSDCJT
```

then try the instructions that follow.

There are two easy-to-use development servers:

An [online test server](https://www.forumsys.com/2022/05/10/online-ldap-test-server/) using a couple of groups of mathematicians and scientists.

```
export VAULT_ADDR=http://127.0.0.1:8200
vault login -method=token token=MlF2MrMpmwfCZOkCHoZSDCJT

vault secrets disable /secret
vault secrets enable -version=1 -path=/secret kv
vault write /secret/password value=mypass
vault read /secret/password

echo 'path "secret/*" { capabilities = ["read"] }' | vault policy write read-secret -

vault auth disable ldap
vault auth enable ldap

vault write auth/ldap/config \
  url="ldap://ldap.forumsys.com" \
  binddn='cn=read-only-admin,dc=example,dc=com' \
  bindpass='password' \
  userdn='dc=example,dc=com' \
  userattr='uid' \
  groupfilter='(uniqueMember={{.UserDN}})' \
  groupdn='dc=example,dc=com' \
  groupattr='ou'

vault write auth/ldap/groups/scientists policies=read-secret

vault login -method=ldap username=einstein password=password
vault read /secret/password
```

(The instructions were worked out using [this forum post](https://groups.google.com/g/vault-tool/c/DKNvMfLf-5w?pli=1))

A docker image [`rroemhild/test-openldap`](https://github.com/rroemhild/docker-test-openldap)

In another terminal, start the LDAP server with:

```
docker run --rm -p 127.0.0.1:10389:10389 rroemhild/test-openldap
```

Then a similar set of commands to before

```
export VAULT_ADDR=http://127.0.0.1:8200
vault login -method=token token=MlF2MrMpmwfCZOkCHoZSDCJT

vault secrets disable /secret
vault secrets enable -version=1 -path=/secret kv
vault write /secret/password value=mypass
vault read /secret/password

echo 'path "secret/*" { capabilities = ["read"] }' | vault policy write read-secret -

vault auth disable ldap
vault auth enable ldap

vault write auth/ldap/config \
  url="ldap://localhost:10389" \
  userdn="ou=people,dc=planetexpress,dc=com" \
  groupdn="ou=people,dc=planetexpress,dc=com" \
  groupattr="cn" \
  userattr=uid \
  binddn="cn=admin,dc=planetexpress,dc=com" \
  bindpass='GoodNewsEveryone'

vault write auth/ldap/groups/admin_staff policies=read-secret

vault login -method=ldap username=hermes password=hermes
vault read /secret/password
```

(The instructions were worked out using [this github issue](https://github.com/hashicorp/vault/issues/6325))

The test suite will use the public forumsys version by default, but set the environment variable `VAULTR_TEST_LDAP_USE_DOCKER` to `true` to use that instead.

```
VAULTR_TEST_LDAP_USE_DOCKER=true
```
