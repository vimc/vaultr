context("secret: transit")


test_that("custom mount", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit", path = "transit2")
  tr <- cl$secrets$transit$custom_mount("transit2")
  expect_is(tr, "vault_client_transit")

  expect_is(tr$random(format = "raw"), "raw")
})


test_that("basic key create/list/update/delete", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit

  expect_null(transit$key_create("test"))
  expect_equal(transit$key_list(), "test")
  transit$key_update("test", deletion_allowed = TRUE)
  info <- transit$key_read("test")
  expect_is(info, "list")
  expect_true(info$deletion_allowed)
  expect_null(transit$key_delete("test"))
  expect_equal(transit$key_list(), character(0))
})


test_that("key rotate", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")
  transit$key_rotate("test")
  dat <- transit$key_read("test")
  expect_setequal(names(dat$keys), c("1", "2"))
})


test_that("encrypt data", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")

  plaintext <- "hello world"
  cyphertext <- transit$data_encrypt("test", charToRaw(plaintext))

  res <- transit$data_decrypt("test", cyphertext)
  expect_is(res, "raw")
  expect_identical(res, charToRaw(plaintext))
})


test_that("rewrap data", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")
  plaintext <- charToRaw("hello world")
  cyphertext1 <- transit$data_encrypt("test", plaintext)
  transit$key_rotate("test")
  cyphertext2 <- transit$data_rewrap("test", cyphertext1)

  expect_identical(transit$data_decrypt("test", cyphertext1), plaintext)
  expect_identical(transit$data_decrypt("test", cyphertext2), plaintext)

  transit$key_update("test", min_decryption_version = 2L,
                     min_encryption_version = 2L)
  expect_error(transit$data_decrypt("test", cyphertext1),
               class = "vault_invalid_request")
})


test_that("datakey", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")

  k1 <- transit$datakey_create("test", plaintext = TRUE)
  k2 <- transit$datakey_create("test", plaintext = FALSE)
  expect_true(all(c("ciphertext", "plaintext") %in% names(k1)))
  expect_true(all("ciphertext" %in% names(k2)))

  expect_silent(transit$data_decrypt("test", k1$ciphertext))
})


## duplicated tests from tools
test_that("random", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$secrets$enable("transit")
  transit <- cl$secrets$transit

  res <- transit$random()
  expect_equal(nchar(res), 64)

  res <- transit$random(format = "base64")
  expect_equal(nchar(res), 44)

  res <- transit$random(format = "raw")
  expect_is(res, "raw")
  expect_equal(length(res), 32)
})


test_that("hash", {
  srv <- vault_test_server()
  cl <- srv$client()
  cl$secrets$enable("transit")
  transit <- cl$secrets$transit

  data <- charToRaw("hello vault")
  expect_equal(
    transit$hash(data),
    "55e702c93bd83f5dc1eabdc7e0c268b8a7626b2e8008a7b96023192efd40c2a4")
  expect_equal(
    transit$hash(data, "sha2-224"),
    "e2a3ef7fdcbf9bb6b862ab2bcddc99b2decebca260ba60ae4c8d58e0")
  expect_equal(
    transit$hash(data, "sha2-384"),
    "08a5d9c42fe137f6299adcf2a583501821f8e1b43648c57ba15c6a9558bd4dd4059edc9ea1303dbf207a8d36ae10b450")
  expect_equal(
    transit$hash(data, "sha2-512"),
    "700bfd8ed566cbdcec20ce39db81aec29d489286a97206cd99824d8db1c2e6b3468848766dd791febb1cf7c4dd7faecc98430891698fbe162badfa502186d380")

  expect_equal(
    transit$hash(data, format = "base64"),
    "VecCyTvYP13B6r3H4MJouKdiay6ACKe5YCMZLv1AwqQ=")

  expect_error(
    transit$hash("data", format = "base64"),
    "Expected raw data")
})


test_that("hmac", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test", key_type = "ecdsa-p256")

  data <- charToRaw("hello world")

  hmac <- transit$hmac("test", data)
  expect_true(transit$verify_hmac("test", data, hmac))
  expect_false(transit$verify_hmac("test", data[-1], hmac))
})


test_that("sign", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test", key_type = "ecdsa-p256")

  data <- charToRaw("hello world")

  signature <- transit$sign("test", data)
  expect_true(transit$verify_signature("test", data, signature))
  expect_false(transit$verify_signature("test", data[-1], signature))
})


test_that("backup", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test", exportable = TRUE, allow_plaintext_backup = TRUE)

  plaintext <- charToRaw("hello world")
  cyphertext <- transit$data_encrypt("test", plaintext)

  key <- transit$key_backup("test")
  expect_is(key, "character")

  transit$key_restore("restored", key)
  expect_identical(transit$data_decrypt("restored", cyphertext), plaintext)
})


test_that("export", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test", exportable = TRUE)


  k <- transit$key_export("test", "encryption-key", NULL)
  expect_is(k, "character")
  expect_equal(transit$key_export("test", "encryption-key", 1),
               setNames(list(k), "1"))
})


test_that("key trim", {
  srv <- vault_test_server()
  skip_if_vault_before("1.0.0", srv, "/transit/keys/:name/trim",
                       "Key trimming")
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit

  transit$key_create("test")
  transit$key_rotate("test")
  transit$key_update("test", min_decryption_version = 2L,
                     min_encryption_version = 2L)
  expect_equal(length(transit$key_read("test")$keys), 1)

  transit$key_update("test", min_decryption_version = 1L,
                     min_encryption_version = 1L)
  expect_equal(length(transit$key_read("test")$keys), 2)

  transit$key_update("test", min_decryption_version = 2L,
                     min_encryption_version = 2L)
  transit$key_trim("test", 2L)
  expect_error(transit$key_update("test", min_decryption_version = 1L,
                                  min_encryption_version = 1L))
  expect_equal(length(transit$key_read("test")$keys), 1)

})


test_that("key derivation: encrypt/decrypt", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit

  transit$key_create("test", derived = TRUE)
  context <- charToRaw("samplecontext")
  plaintext <- charToRaw("plaintext")

  cyphertext <- transit$data_encrypt("test", plaintext, context = context)
  expect_identical(transit$data_decrypt("test", cyphertext, context = context),
                   plaintext)
  expect_error(transit$data_decrypt("test", cyphertext), "context",
               class = "vault_invalid_request")
})


test_that("key derivation: rewrap", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")
  plaintext <- charToRaw("hello world")
  context <- charToRaw("samplecontext")
  cyphertext1 <- transit$data_encrypt("test", plaintext, context = context)
  transit$key_rotate("test")
  cyphertext2 <- transit$data_rewrap("test", cyphertext1, context = context)

  expect_identical(
    transit$data_decrypt("test", cyphertext1, context = context),
    plaintext)
  expect_identical(
    transit$data_decrypt("test", cyphertext2, context = context),
    plaintext)

  transit$key_update("test", min_decryption_version = 2L,
                     min_encryption_version = 2L)
  expect_error(transit$data_decrypt("test", cyphertext1, context = context),
               class = "vault_invalid_request")
})


test_that("key derivation: datakey", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test")
  context <- charToRaw("samplecontext")

  k1 <- transit$datakey_create("test", plaintext = TRUE, context = context)
  expect_true(all(c("ciphertext", "plaintext") %in% names(k1)))

  expect_silent(transit$data_decrypt("test", k1$ciphertext, context = context))
})


test_that("key derivation: sign/verify", {
  srv <- vault_test_server()
  cl <- srv$client()

  cl$secrets$enable("transit")
  transit <- cl$secrets$transit
  transit$key_create("test", key_type = "ed25519", derived = TRUE)
  transit$key_read("test")

  data <- charToRaw("hello world")
  context <- charToRaw("samplecontext")

  signature <- transit$sign("test", data, context = context)
  expect_true(transit$verify_signature("test", data, signature,
                                       context = context))
  expect_false(transit$verify_signature("test", data[-1], signature,
                                        context = context))
  expect_error(transit$verify_signature("test", data, signature),
               "context",
               class = "vault_internal_server_error")
})
