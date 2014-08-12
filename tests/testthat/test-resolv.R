context("resolv core")

test_that("we can use the ldns library", {
  
  # success
  expect_that(resolv_a("etsy.com"), is_a("character"))
  expect_that(resolv_txt("google.com"), is_a("character"))
  expect_that(resolv_mx("securitymetrics.org"), is_a("list"))
  expect_that(resolv_cname("www.paypal.com"), is_a("character"))
  expect_that(resolv_ptr("69.28.187.45"), is_a("character"))
  expect_that(resolv_srv("_xmpp-server._tcp.gmail.com."), is_a("list"))
  
})

