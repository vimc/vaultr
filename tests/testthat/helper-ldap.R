ldap_configure <- function(object) {
  use_docker <- Sys_getenv("VAULTR_TEST_LDAP_USE_DOCKER", "false")
  if (tolower(use_docker) == "true") {
    ldap_configure_docker(object)
  } else {
    ldap_configure_public(object)
  }
}


ldap_configure_docker <- function(object) {
  configuration <- list(
    url = "ldap://localhost:10389",
    binddn = "cn=admin,dc=planetexpress,dc=com",
    bindpass = "GoodNewsEveryone",
    userdn = "ou=people,dc=planetexpress,dc=com",
    userattr = "uid",
    groupdn = "ou=people,dc=planetexpress,dc=com",
    groupattr = "cn")
  do.call(object$configure, configuration)
  list(username = "hermes",
       password = "hermes",
       group = "admin_staff",
       configuration = configuration)
}


ldap_configure_public <- function(object) {
  configuration <- list(
    url = "ldap://ldap.forumsys.com",
    binddn = "cn=read-only-admin,dc=example,dc=com",
    bindpass = "password",
    userdn = "dc=example,dc=com",
    userattr = "uid",
    groupdn = "dc=example,dc=com",
    groupattr = "ou",
    groupfilter = "(uniqueMember={{.UserDN}})")
  do.call(object$configure, configuration)
  list(username = "einstein",
       password = "password",
       group = "scientists",
       configuration = configuration)
}
