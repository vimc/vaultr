backend "inmem" {
}

listener "tcp" {
  tls_cert_file = "VAULT_CONFIG_PATH/server-cert.pem"
  tls_key_file  = "VAULT_CONFIG_PATH/server-key.pem"
  address       = "VAULT_ADDR"
}

disable_mlock = true
