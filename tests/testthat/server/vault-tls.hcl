backend "inmem" {
}

listener "tcp" {
  tls_cert_file = "server/server-cert.pem"
  tls_key_file  = "server/server-key.pem"
}

disable_mlock = true
