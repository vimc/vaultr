##' Interact with vault's \code{transit} engine.  This is useful for
##' encrypting arbitrary data without storing it in the vault - like
##' "cryptography as a service" or "encryption as a service". The
##' transit secrets engine can also sign and verify data; generate
##' hashes and HMACs of data; and act as a source of random bytes.
##' See
##' \href{https://www.vaultproject.io/docs/secrets/transit/index.html}{https://www.vaultproject.io/docs/secrets/transit/index.html}
##' for an introduction to the capabilities of the \code{transit}
##' engine.
##'
##' @template vault_client_transit
##'
##' @title Transit Engine
##' @name vault_client_transit
NULL


R6_vault_client_transit <- R6::R6Class(
  "vault_client_transit",

  private = list(
    api_client = NULL,
    mount = NULL
  ),

  public = list(
    initialize = function(api_client, mount) {
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    format = function(brief = FALSE) {
      vault_client_format(self, brief, "transit",
                          "Cryptographic functions for data in-transit")
    },

    custom_mount = function(mount) {
      R6_vault_client_transit$new(private$api_client, mount)
    },

    key_create = function(name, key_type = NULL, convergent_encryption = NULL,
                          derived = NULL, exportable = NULL,
                          allow_plaintext_backup = NULL) {
      path <- sprintf("/%s/keys/%s", private$mount,
                      assert_scalar_character(name))
      body <- list(
        type = key_type %&&% assert_scalar_character(key_type),
        convergent_encryption = convergent_encryption %&&%
          assert_scalar_logical(convergent_encryption),
        derived = derived %&&% assert_scalar_logical(derived),
        exportable = exportable %&&% assert_scalar_logical(exportable),
        allow_plaintext_backup = allow_plaintext_backup %&&%
          assert_scalar_logical(allow_plaintext_backup))
      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    key_read = function(name) {
      path <- sprintf("/%s/keys/%s", private$mount,
                      assert_scalar_character(name))
      private$api_client$GET(path)$data
    },

    key_list = function() {
      data <- tryCatch(
        private$api_client$LIST(sprintf("/%s/keys", private$mount)),
        vault_invalid_path = function(e) NULL)
      list_to_character(data$data$keys)
    },

    key_delete = function(name) {
      path <- sprintf("/%s/keys/%s", private$mount,
                      assert_scalar_character(name))
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    key_update = function(name, min_decryption_version = NULL,
                          min_encryption_version = NULL,
                          deletion_allowed = NULL,
                          exportable = NULL,
                          allow_plaintext_backup = NULL) {
      path <- sprintf("/%s/keys/%s/config", private$mount,
                      assert_scalar_character(name))
      body <- list(
        min_decryption_version = min_decryption_version %&&%
          assert_scalar_integer(min_decryption_version),
        min_encryption_version = min_encryption_version %&&%
          assert_scalar_integer(min_encryption_version),
        deletion_allowed = deletion_allowed %&&%
          assert_scalar_logical(deletion_allowed),
        exportable = exportable %&&% assert_scalar_integer(exportable),
        allow_plaintext_backup = allow_plaintext_backup %&&%
          assert_scalar_integer(allow_plaintext_backup))
      private$api_client$POST(path, body = drop_null(body))
      invisible(NULL)
    },

    key_rotate = function(name) {
      path <- sprintf("/%s/keys/%s/rotate", private$mount,
                      assert_scalar_character(name))
      private$api_client$POST(path)
      invisible(NULL)
    },

    ## https://github.com/hashicorp/vault/issues/2667
    ##
    ## > Part of the "contract" of transit is that the key is never
    ## > exposed outside of Vault. We added the ability to export keys
    ## > because some enterprises have key escrow requirements, but it
    ## > leaves a permanent mark in the key metadata. I suppose we
    ## > could at some point allow importing a key and also leave such
    ## > a mark.
    key_export = function(name, key_type, version = NULL) {
      assert_scalar_character(name)
      assert_scalar_character(key_type)
      if (is.null(version)) {
        path <- sprintf("/%s/export/%s/%s",
                        private$mount, key_type, name)
      } else {
        assert_scalar_integer(version)
        path <- sprintf("/%s/export/%s/%s/%d",
                        private$mount, key_type, name, version)
      }
      keys <- private$api_client$GET(path)$data$keys
      if (is.null(version)) keys[[1]] else keys
    },

    data_encrypt = function(key_name, data, key_version = NULL,
                            context = NULL) {
      ## nonce = not accepted
      ## batch_input = different interface
      ## type, convergent_encryption = not clear at this point
      body <- list(
        plaintext = raw_data_input(data),
        context = context %&&% raw_data_input(context),
        key_version = key_version %&&% assert_scalar_integer(key_version))
      path <- sprintf("/%s/encrypt/%s",
                      private$mount, assert_scalar_character(key_name))
      data <- private$api_client$POST(path, body = drop_null(body))$data
      data$ciphertext
    },

    data_decrypt = function(key_name, data, context = NULL) {
      ## nonce = not accepted
      ## batch_input = different interface
      body <- list(
        ciphertext = assert_scalar_character(data),
        context = context %&&% raw_data_input(context))
      path <- sprintf("/%s/decrypt/%s",
                      private$mount, assert_scalar_character(key_name))
      data <- private$api_client$POST(path, body = drop_null(body))$data
      decode64(data$plaintext)
    },

    data_rewrap = function(key_name, data, key_version = NULL,
                           context = NULL) {
      ## nonce = not accepted
      ## batch_input = different interface
      body <- list(
        context = context %&&% raw_data_input(context),
        ciphertext = assert_scalar_character(data))
      path <- sprintf("/%s/rewrap/%s",
                      private$mount, assert_scalar_character(key_name))
      data <- private$api_client$POST(path, body = drop_null(body))$data
      data$ciphertext
    },

    ## https://groups.google.com/forum/#!topic/vault-tool/gEjLRWlc6C4
    datakey_create = function(name, plaintext = FALSE, bits = NULL,
                              context = NULL) {
      assert_scalar_character(name)
      assert_scalar_logical(plaintext)
      datakey_type <- if (plaintext) "plaintext" else "wrapped"
      path <- sprintf("%s/datakey/%s/%s", private$mount, datakey_type, name)
      body <- list(bits = bits %&&% assert_scalar_integer(bits),
                   context = context %&&% raw_data_input(context))
      private$api_client$POST(path, body = drop_null(body))$data
    },

    random = function(bytes = 32, format = "hex") {
      bytes <- assert_scalar_integer(bytes)
      body <- list(bytes = assert_scalar_integer(bytes),
                   format = assert_scalar_character(format))
      if (format == "raw") {
        body$format <- "base64"
      }
      path <- sprintf("/%s/random", private$mount)
      res <- private$api_client$POST(path, body = body)
      bytes <- res$data$random_bytes
      if (format == "raw") {
        decode64(bytes)
      } else {
        bytes
      }
    },

    hash = function(data, algorithm = NULL, format = "hex") {
      path <- sprintf("/%s/hash", private$mount)
      body <- list(
        input = raw_data_input(data),
        algorithm = algorithm %&&% assert_scalar_character(algorithm),
        format = assert_scalar_character(format))
      private$api_client$POST(path, body = drop_null(body))$data$sum
    },

    hmac = function(name, data, key_version = NULL, algorithm = NULL) {
      path <- sprintf("/%s/hmac/%s",
                      private$mount, assert_scalar_character(name))
      body <- list(
        key_version = key_version %&&% assert_scalar_integer(key_version),
        algorithm = algorithm %&&% assert_scalar_character(algorithm),
        input = raw_data_input(data))
      private$api_client$POST(path, body = drop_null(body))$data$hmac
    },

    sign = function(name, data, key_version = NULL, hash_algorithm = NULL,
                    prehashed = FALSE, signature_algorithm = NULL,
                    context = NULL) {
      path <- sprintf("/%s/sign/%s",
                      private$mount, assert_scalar_character(name))
      body <- list(
        key_version = key_version %&&% assert_scalar_integer(key_version),
        hash_algorithm =
          hash_algorithm %&&% assert_scalar_integer(hash_algorithm),
        signature_algorithm =
          signature_algorithm %&&% assert_scalar_integer(signature_algorithm),
        input = raw_data_input(data),
        context = context %&&% raw_data_input(context),
        prehashed = assert_scalar_logical(prehashed))
      private$api_client$POST(path, body = drop_null(body))$data$signature
    },

    verify = function(name, data, payload, payload_type,
                      hash_algorithm = NULL,
                      signature_algorithm = NULL,
                      context = NULL, prehashed = FALSE) {
      path <- sprintf("/%s/verify/%s",
                      private$mount, assert_scalar_character(name))
      payload_type <- match_value(payload_type, c("signature", "hmac"))
      body <- list(
        hash_algorithm =
          hash_algorithm %&&% assert_scalar_integer(hash_algorithm),
        input = raw_data_input(data),
        context = context %&&% raw_data_input(context),
        prehashed = assert_scalar_logical(prehashed),
        signature_algorithm =
          signature_algorithm %&&% assert_scalar_integer(signature_algorithm))
      body[[payload_type]] <- assert_scalar_character(payload)
      private$api_client$POST(path, body = drop_null(body))$data$valid
    },

    verify_signature = function(name, data, signature, hash_algorithm = NULL,
                                signature_algorithm = NULL, context = NULL,
                                prehashed = FALSE) {
      self$verify(name, data, signature, "signature",
                  hash_algorithm, signature_algorithm,
                  context, prehashed)
    },

    verify_hmac = function(name, data, signature, hash_algorithm = NULL,
                           signature_algorithm = NULL, context = NULL,
                           prehashed = FALSE) {
      self$verify(name, data, signature, "hmac",
                  hash_algorithm, signature_algorithm,
                  context, prehashed)
    },

    key_backup = function(name) {
      path <- sprintf("/%s/backup/%s",
                      private$mount, assert_scalar_character(name))
      private$api_client$GET(path)$data$backup
    },

    key_restore = function(name, backup, force = FALSE) {
      path <- sprintf("/%s/restore/%s",
                      private$mount, assert_scalar_character(name))
      body <- list(backup = assert_scalar_character(backup),
                   force = assert_scalar_logical(force))
      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    key_trim = function(name, min_version) {
      path <- sprintf("/%s/keys/%s/trim",
                      private$mount, assert_scalar_character(name))
      assert_vault_version("0.11.4", private$api_client, path,
                           "transit key trim")
      ## TODO: this differs from the spec here:
      ## https://www.vaultproject.io/api/secret/transit/index.html#trim-key
      ## (claims min_version)
      body <- list(min_available_version = assert_scalar_integer(min_version))
      private$api_client$POST(path, body = body)
    }
  ))
