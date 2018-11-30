context("vault: policy")


test_that("read policy", {
  srv <- vault_test_server()
  cl <- srv$client()

  ## There's not much we can take from this one yet - this gets a
  ## better test after we start *writing* policies
  rules <- cl$policy$read("default")
  expect_is(rules, "character")
})


test_that("write_policy", {
  srv <- vault_test_server()
  cl <- srv$client()

  rules <- paste('path "secret/*" {',
                 '  policy = "read"',
                 '}',
                 sep = "\n")
  cl$policy$write("read-secret", rules)
  expect_true("read-secret" %in% cl$policy$list())
  expect_equal(cl$policy$read("read-secret"), rules)
  cl$policy$delete("read-secret")
  expect_false("read-secret" %in% cl$policy$list())
})
