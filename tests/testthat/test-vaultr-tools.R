test_that("random", {
  srv <- vault_test_server()
  cl <- srv$client()

  res <- cl$tools$random()
  expect_equal(nchar(res), 64)

  res <- cl$tools$random(format = "base64")
  expect_equal(nchar(res), 44)

  res <- cl$tools$random(format = "raw")
  expect_type(res, "raw")
  expect_equal(length(res), 32)
})


test_that("hash", {
  srv <- vault_test_server()
  cl <- srv$client()

  data <- charToRaw("hello vault")
  expect_equal(
    cl$tools$hash(data),
    "55e702c93bd83f5dc1eabdc7e0c268b8a7626b2e8008a7b96023192efd40c2a4")
  expect_equal(
    cl$tools$hash(data, "sha2-224"),
    "e2a3ef7fdcbf9bb6b862ab2bcddc99b2decebca260ba60ae4c8d58e0")
  expect_equal(
    cl$tools$hash(data, "sha2-384"),
    paste0(
      "08a5d9c42fe137f6299adcf2a583501821f8e1b43648c57ba15c6a9558bd4dd4059edc",
      "9ea1303dbf207a8d36ae10b450"))
  expect_equal(
    cl$tools$hash(data, "sha2-512"),
    paste0(
      "700bfd8ed566cbdcec20ce39db81aec29d489286a97206cd99824d8db1c2e6b3468848",
      "766dd791febb1cf7c4dd7faecc98430891698fbe162badfa502186d380"))

  expect_equal(
    cl$tools$hash(data, format = "base64"),
    "VecCyTvYP13B6r3H4MJouKdiay6ACKe5YCMZLv1AwqQ=")

  expect_error(
    cl$tools$hash("data", format = "base64"),
    "Expected raw data")
})
