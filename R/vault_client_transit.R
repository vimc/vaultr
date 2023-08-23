##' Interact with vault's `transit` engine.  This is useful for
##' encrypting arbitrary data without storing it in the vault - like
##' "cryptography as a service" or "encryption as a service". The
##' transit secrets engine can also sign and verify data; generate
##' hashes and HMACs of data; and act as a source of random bytes.
##' See
##' https://developer.hashicorp.com/vault/docs/secrets/transit
##' for an introduction to the capabilities of the `transit`
##' engine.
##'
##' @title Transit Engine
##' @name vault_client_transit
##' @examples
##' server <- vaultr::vault_test_server(if_disabled = message)
##' if (!is.null(server)) {
##'   client <- server$client()
##'
##'   client$secrets$enable("transit")
##'   transit <- client$secrets$transit
##'
##'   # Before encrypting anything, create a key.  Note that it will
##'   # not be returned to you, and is accessed purely by name
##'   transit$key_create("test")
##'
##'   # Some text to encrypt
##'   plaintext <- "hello world"
##'
##'   # Encrypted:
##'   cyphertext <- transit$data_encrypt("test", charToRaw(plaintext))
##'
##'   # Decrypt the data
##'   res <- transit$data_decrypt("test", cyphertext)
##'   rawToChar(res)
##'
##'   # This approach works with R objects too, if used with serialise.
##'   # First, serialise an R object to a raw vector:
##'   data <- serialize(mtcars, NULL)
##'
##'   # Then encrypt this data:
##'   enc <- transit$data_encrypt("test", data)
##'
##'   # The resulting string can be safely passed around (e.g., over
##'   # email) or written to disk, and can later be decrypted by
##'   # anyone who has access to the "test" key in the vault:
##'   data2 <- transit$data_decrypt("test", enc)
##'
##'   # Once decrypted, the data can be "unserialised" back into an R
##'   # object:
##'   unserialize(data2)
##'
##'   # cleanup
##'   server$kill()
##' }
vault_client_transit <- R6::R6Class(
  "vault_client_transit",
  inherit = vault_client_object,
  cloneable = FALSE,

  private = list(
    api_client = NULL,
    mount = NULL,

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
    }
  ),

  public = list(
    ##' @description Create a `vault_client_transit` object. Not typically
    ##'   called by users.
    ##'
    ##' @param api_client A [vaultr::vault_api_client] object
    ##'
    ##' @param mount Mount point for the backend
   initialize = function(api_client, mount) {
      super$initialize("Cryptographic functions for data in-transit")
      assert_scalar_character(mount)
      private$mount <- sub("^/", "", mount)
      private$api_client <- api_client
    },

    ##' @description Set up a `vault_client_transit` object at a custom
    ##'   mount.  For example, suppose you mounted the `transit` secret
    ##'   backend at `/transit2` you might use `tr <-
    ##'   vault$secrets$transit$custom_mount("/transit2")` - this
    ##'   pattern is repeated for other secret and authentication
    ##'   backends.
    ##'
    ##' @param mount String, indicating the path that the engine is
    ##'   mounted at.
    custom_mount = function(mount) {
      vault_client_transit$new(private$api_client, mount)
    },

    ##' @description Create a new named encryption key of the specified
    ##'   type. The values set here cannot be changed after key
    ##'   creation.
    ##'
    ##' @param name Name for the key.  This will be used in all future
    ##'   interactions with the key - the key itself is not returned.
    ##'
    ##' @param key_type Specifies the type of key to create.  The default is
    ##'   `aes256-gcm96`. The currently-supported types are:
    ##'
    ##' * `aes256-gcm96`: AES-256 wrapped with GCM using a 96-bit nonce
    ##'   size AEAD (symmetric, supports derivation and convergent
    ##'   encryption)
    ##'
    ##' * `chacha20-poly1305`: ChaCha20-Poly1305 AEAD (symmetric,
    ##'    supports derivation and convergent encryption)
    ##'
    ##' * `ed25519`: ED25519 (asymmetric, supports derivation). When
    ##'   using derivation, a sign operation with the same context will
    ##'   derive the same key and signature; this is a signing analogue
    ##'   to `convergent_encryption`
    ##'
    ##' * `ecdsa-p256`: ECDSA using the P-256 elliptic curve
    ##'   (asymmetric)
    ##'
    ##' * `rsa-2048`: RSA with bit size of 2048 (asymmetric)
    ##'
    ##' * `rsa-4096`: RSA with bit size of 4096 (asymmetric)
    ##'
    ##' @param convergent_encryption Logical with default of `FALSE`.
    ##'   If `TRUE`, then the key will support convergent encryption,
    ##'   where the same plaintext creates the same ciphertext. This
    ##'   requires derived to be set to true. When enabled, each
    ##'   encryption(/decryption/rewrap/datakey) operation will derive
    ##'   a `nonce` value rather than randomly generate it.
    ##'
    ##' @param derived Specifies if key derivation is to be used. If
    ##'   enabled, all encrypt/decrypt requests to this named key must
    ##'   provide a context which is used for key derivation (default
    ##'   is `FALSE`).
    ##'
    ##' @param exportable Enables keys to be exportable. This allows
    ##'   for all the valid keys in the key ring to be exported. Once
    ##'   set, this cannot be disabled (default is `FALSE`).
    ##'
    ##' @param allow_plaintext_backup If set, enables taking backup of
    ##'   named key in the plaintext format. Once set, this cannot be
    ##'   disabled (default is `FALSE`).
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

    ##' @description Read information about a previously generated key.
    ##'   The returned object shows the creation time of each key
    ##'   version; the values are not the keys themselves. Depending on
    ##'   the type of key, different information may be returned,
    ##'   e.g. an asymmetric key will return its public key in a
    ##'   standard format for the type.
    ##'
    ##' @param name The name of the key to read
    key_read = function(name) {
      path <- sprintf("/%s/keys/%s", private$mount,
                      assert_scalar_character(name))
      private$api_client$GET(path)$data
    },

    ##' @description List names of all keys
    key_list = function() {
      data <- tryCatch(
        private$api_client$LIST(sprintf("/%s/keys", private$mount)),
        vault_invalid_path = function(e) NULL)
      list_to_character(data$data$keys)
    },

    ##' @description Delete a key by name.  It will no longer be
    ##'   possible to decrypt any data encrypted with the named
    ##'   key. Because this is a potentially catastrophic operation,
    ##'   the `deletion_allowed` tunable must be set using
    ##'   `$key_update()`.
    ##'
    ##' @param name The name of the key to delete.
    key_delete = function(name) {
      path <- sprintf("/%s/keys/%s", private$mount,
                      assert_scalar_character(name))
      private$api_client$DELETE(path)
      invisible(NULL)
    },

    ##' @description This method allows tuning configuration values for
    ##'   a given key. (These values are returned during a read
    ##'   operation on the named key.)
    ##'
    ##' @param name The name of the key to update
    ##'
    ##' @param min_decryption_version Specifies the minimum version of
    ##'   ciphertext allowed to be decrypted, as an integer (default is
    ##'   `0`). Adjusting this as part of a key rotation policy can
    ##'   prevent old copies of ciphertext from being decrypted, should
    ##'   they fall into the wrong hands. For signatures, this value
    ##'   controls the minimum version of signature that can be
    ##'   verified against. For HMACs, this controls the minimum
    ##'   version of a key allowed to be used as the key for
    ##'   verification.
    ##'
    ##' @param min_encryption_version Specifies the minimum version of
    ##'   the key that can be used to encrypt plaintext, sign payloads,
    ##'   or generate HMACs, as an integer (default is `0`).  Must be 0
    ##'   (which will use the latest version) or a value greater or
    ##'   equal to `min_decryption_version`.
    ##'
    ##' @param deletion_allowed Specifies if the key is allowed to be
    ##'   deleted, as a logical (default is `FALSE`).
    ##'
    ##' @param exportable Enables keys to be exportable. This allows
    ##'   for all the valid keys in the key ring to be exported. Once
    ##'   set, this cannot be disabled.
    ##'
    ##' @param allow_plaintext_backup If set, enables taking backup of
    ##'   named key in the plaintext format. Once set, this cannot be
    ##'   disabled.
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

    ##' @description Rotates the version of the named key. After
    ##'   rotation, new plaintext requests will be encrypted with the
    ##'   new version of the key. To upgrade ciphertext to be encrypted
    ##'   with the latest version of the key, use the rewrap
    ##'   endpoint. This is only supported with keys that support
    ##'   encryption and decryption operations.
    ##'
    ##' @param name The name of the key to rotate
    key_rotate = function(name) {
      path <- sprintf("/%s/keys/%s/rotate", private$mount,
                      assert_scalar_character(name))
      private$api_client$POST(path)
      invisible(NULL)
    },

    ##' @description Export the named key. If version is specified, the
    ##'   specific version will be returned. If latest is provided as
    ##'   the version, the current key will be provided. Depending on
    ##'   the type of key, different information may be returned. The
    ##'   key must be exportable to support this operation and the
    ##'   version must still be valid.
    ##'
    ##' For more details see
    ##'   https://github.com/hashicorp/vault/issues/2667 where
    ##'   HashiCorp says "Part of the "contract" of transit is that the
    ##'   key is never exposed outside of Vault. We added the ability
    ##'   to export keys because some enterprises have key escrow
    ##'   requirements, but it leaves a permanent mark in the key
    ##'   metadata. I suppose we could at some point allow importing a
    ##'   key and also leave such a mark."
    ##'
    ##' @param name Name of the key to export
    ##'
    ##' @param key_type Specifies the type of the key to export. Valid
    ##'   values are `encryption-key`, `signing-key` and `hmac-key`.
    ##'
    ##' @param version Specifies the version of the key to read. If
    ##'   omitted, all versions of the key will be returned. If the
    ##'   version is set to latest, the current key will be returned
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

    ##' @description This endpoint encrypts the provided plaintext
    ##'   using the named key.
    ##'
    ##' @param key_name Specifies the name of the encryption key to
    ##'   encrypt against.
    ##'
    ##' @param data Data to encrypt, as a raw vector
    ##'
    ##' @param key_version Key version to use, as an integer. If not
    ##'   set, uses the latest version. Must be greater than or equal
    ##'   to the key's `min_encryption_version`, if set.
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
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

    ##' @description Decrypts the provided ciphertext using the named
    ##' key.
    ##'
    ##' @param key_name Specifies the name of the encryption key to
    ##'   decrypt with.
    ##'
    ##' @param data The data to decrypt.  Must be a string, as returned
    ##'   by `$data_encrypt`.
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
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

    ##' @description Rewraps the provided ciphertext using the latest
    ##'   version of the named key. Because this never returns
    ##'   plaintext, it is possible to delegate this functionality to
    ##'   untrusted users or scripts.
    ##'
    ##' @param key_name Specifies the name of the encryption key to
    ##'   re-encrypt against
    ##'
    ##' @param data The data to decrypt.  Must be a string, as returned
    ##'   by `$data_encrypt`.
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
    ##'
    ##' @param key_version Specifies the version of the key to use for
    ##'   the operation. If not set, uses the latest version. Must be
    ##'   greater than or equal to the key's `min_encryption_version`,
    ##'   if set.
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

    ##' @description This endpoint generates a new high-entropy key and
    ##'   the value encrypted with the named key. Optionally return the
    ##'   plaintext of the key as well.
    ##'
    ##' @param name Specifies the name of the encryption key to use to
    ##'   encrypt the datakey
    ##'
    ##' @param plaintext Logical, indicating if the plaintext key
    ##'   should be returned.
    ##'
    ##' @param bits Specifies the number of bits in the desired
    ##'   key. Can be 128, 256, or 512.
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
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

    ##' @description Generates high-quality random bytes of the
    ##'   specified length.  This is totally independent of R's random
    ##'   number stream and provides random numbers suitable for
    ##'   cryptographic purposes.
    ##'
    ##' @param bytes Number of bytes to generate (as an integer)
    ##'
    ##' @param format The output format to produce; must be one of
    ##'   `hex` (a single hex string such as `d1189e2f83b72ab6`),
    ##'   `base64` (a single base64 encoded string such as
    ##'   `8TDJekY0mYs=`) or `raw` (a raw vector of length `bytes`).
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

    ##' @description Generates a cryptographic hash of given data using
    ##'   the specified algorithm.
    ##'
    ##' @param data A raw vector of data to hash.  To generate a raw
    ##'   vector from an R object, one option is to use `unserialize(x,
    ##'   NULL)` but be aware that version information may be included.
    ##'   Alternatively, for a string, one might use `charToRaw`.
    ##'
    ##' @param algorithm A string indicating the hash algorithm to use.
    ##'   The exact set of supported algorithms may depend by vault
    ##'   server version, but as of version 1.0.0 vault supports
    ##'   `sha2-224`, `sha2-256`, `sha2-384` and `sha2-512`.  The
    ##'   default is `sha2-256`.
    ##'
    ##' @param format The format of the output - must be one of `hex`
    ##'   or `base64`.
    hash = function(data, algorithm = NULL, format = "hex") {
      path <- sprintf("/%s/hash", private$mount)
      body <- list(
        input = raw_data_input(data),
        algorithm = algorithm %&&% assert_scalar_character(algorithm),
        format = assert_scalar_character(format))
      private$api_client$POST(path, body = drop_null(body))$data$sum
    },

    ##' @description This endpoint returns the digest of given data
    ##'   using the specified hash algorithm and the named key. The key
    ##'   can be of any type supported by the `transit` engine; the raw
    ##'   key will be marshalled into bytes to be used for the HMAC
    ##'   function. If the key is of a type that supports rotation, the
    ##'   latest (current) version will be used.
    ##'
    ##' @param name Specifies the name of the encryption key to
    ##'   generate hmac against
    ##'
    ##' @param data The input data, as a raw vector
    ##'
    ##' @param key_version Specifies the version of the key to use for
    ##'   the operation. If not set, uses the latest version. Must be
    ##'   greater than or equal to the key's `min_encryption_version`,
    ##'   if set.
    ##'
    ##' @param algorithm Specifies the hash algorithm to
    ##'   use. Currently-supported algorithms are `sha2-224`,
    ##'   `sha2-256`, `sha2-384` and `sha2-512`.  The default is
    ##'   `sha2-256`.
    hmac = function(name, data, key_version = NULL, algorithm = NULL) {
      path <- sprintf("/%s/hmac/%s",
                      private$mount, assert_scalar_character(name))
      body <- list(
        key_version = key_version %&&% assert_scalar_integer(key_version),
        algorithm = algorithm %&&% assert_scalar_character(algorithm),
        input = raw_data_input(data))
      private$api_client$POST(path, body = drop_null(body))$data$hmac
    },

    ##' @description Returns the cryptographic signature of the given
    ##'   data using the named key and the specified hash
    ##'   algorithm. The key must be of a type that supports signing.
    ##'
    ##' @param name Specifies the name of the encryption key to use for
    ##'   signing
    ##'
    ##' @param data The input data, as a raw vector
    ##'
    ##' @param hash_algorithm Specifies the hash algorithm to
    ##'   use. Currently-supported algorithms are `sha2-224`,
    ##'   `sha2-256`, `sha2-384` and `sha2-512`.  The default is
    ##'   `sha2-256`.
    ##'
    ##' @param prehashed Set to true when the input is already
    ##'   hashed. If the key type is `rsa-2048` or `rsa-4096`, then the
    ##'   algorithm used to hash the input should be indicated by the
    ##'   `hash_algorithm` parameter.
    ##'
    ##' @param signature_algorithm When using a RSA key, specifies the
    ##'   RSA signature algorithm to use for signing. Supported
    ##'   signature types are `pss` (the default) and `pkcs1v15`.
    ##'
    ##' @param key_version Specifies the version of the key to use for
    ##'   signing. If not set, uses the latest version. Must be greater
    ##'   than or equal to the key's `min_encryption_version`, if set.
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
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

    ##' @description Determine whether the provided signature is valid
    ##'     for the given data.
    ##'
    ##' @param name Name of the key
    ##'
    ##' @param data Data to verify, as a raw vector
    ##'
    ##' @param signature The signed data, as a string.
    ##'
    ##' @param hash_algorithm Specifies the hash algorithm to use. This
    ##'   can also be specified as part of the URL (see `$sign` and
    ##'   `$hmac` for details).
    ##'
    ##' @param signature_algorithm When using a RSA key, specifies the
    ##'   RSA signature algorithm to use for signature verification
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
    ##'
    ##' @param prehashed Set to `TRUE` when the input is already hashed
    verify_signature = function(name, data, signature, hash_algorithm = NULL,
                                signature_algorithm = NULL, context = NULL,
                                prehashed = FALSE) {
      private$verify(name, data, signature, "signature",
                     hash_algorithm, signature_algorithm,
                     context, prehashed)
    },

    ##' @description Determine whether the provided signature is valid
    ##'   for the given data.
    ##'
    ##' @param name Name of the key
    ##'
    ##' @param data Data to verify, as a raw vector
    ##'
    ##' @param signature The signed data, as a string.
    ##'
    ##' @param hash_algorithm Specifies the hash algorithm to use. This
    ##'   can also be specified as part of the URL (see `$sign` and
    ##'   `$hmac` for details).
    ##'
    ##' @param signature_algorithm When using a RSA key, specifies the
    ##'   RSA signature algorithm to use for signature verification
    ##'
    ##' @param context Specifies the context for key derivation. This
    ##'   is required if key derivation is enabled for this key.  Must
    ##'   be a raw vector.
    ##'
    ##' @param prehashed Set to `TRUE` when the input is already hashed
    verify_hmac = function(name, data, signature, hash_algorithm = NULL,
                           signature_algorithm = NULL, context = NULL,
                           prehashed = FALSE) {
      private$verify(name, data, signature, "hmac",
                     hash_algorithm, signature_algorithm,
                     context, prehashed)
    },

    ##' @description Returns a plaintext backup of a named key. The
    ##'   backup contains all the configuration data and keys of all
    ##'   the versions along with the HMAC key. The response from this
    ##'   endpoint can be used with `$key_restore` to restore the key.
    ##'
    ##' @param name Name of the key to backup
    key_backup = function(name) {
      path <- sprintf("/%s/backup/%s",
                      private$mount, assert_scalar_character(name))
      private$api_client$GET(path)$data$backup
    },

    ##' @description Restores the backup as a named key. This will
    ##'   restore the key configurations and all the versions of the
    ##'   named key along with HMAC keys. The input to this method
    ##'   should be the output of `$key_restore` method.
    ##'
    ##' @param name Name of the restored key.
    ##'
    ##' @param backup Backed up key data to be restored. This should be
    ##'   the output from the `$key_backup` endpoint.
    ##'
    ##' @param force Logical.  If `TRUE`, then force the restore to
    ##'   proceed even if a key by this name already exists.
    key_restore = function(name, backup, force = FALSE) {
      path <- sprintf("/%s/restore/%s",
                      private$mount, assert_scalar_character(name))
      body <- list(backup = assert_scalar_character(backup),
                   force = assert_scalar_logical(force))
      private$api_client$POST(path, body = body)
      invisible(NULL)
    },

    ##' @description This endpoint trims older key versions setting a
    ##'   minimum version for the keyring. Once trimmed, previous
    ##'   versions of the key cannot be recovered.
    ##'
    ##' @param name Key to trim
    ##'
    ##' @param min_version The minimum version for the key ring. All
    ##'   versions before this version will be permanently
    ##'   deleted. This value can at most be equal to the lesser of
    ##'   `min_decryption_version` and `min_encryption_version`. This
    ##'   is not allowed to be set when either `min_encryption_version`
    ##'   or `min_decryption_version` is set to zero.
    key_trim = function(name, min_version) {
      path <- sprintf("/%s/keys/%s/trim",
                      private$mount, assert_scalar_character(name))
      assert_vault_version("0.11.4", private$api_client, path,
                           "transit key trim")
      ## TODO: this differs from the spec here:
      ## https://developer.hashicorp.com/vault/api-docs/secret/transit#trim-key
      ## (claims min_version)
      body <- list(min_available_version = assert_scalar_integer(min_version))
      private$api_client$POST(path, body = body)
    }
  ))
