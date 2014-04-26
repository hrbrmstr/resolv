\name{resolv_txt}
\alias{resolv_txt}
\title{Returns the DNS TXT records for a FQDN}
\usage{
resolv_txt(fqdn)
}
\arguments{
  \item{fqdn}{input character vector (FQDN)}
}
\value{
vector of TXT records or \code{NULL} if none
}
\description{
Returns the DNS TXT records for a FQDN
}
\examples{
require(resolv)

## get the TXT record for Google
resolv_txt("google.com")
[1] "\\"v=spf1 include:_spf.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all\\""

## get the TXT records for PayPal
resolv_txt("paypal.com")
[1] "\\"MS=ms96239109\\""
[2] "\\"yandex-verification: 73acb90f6a9abd76\\""
[3] "\\"google-site-verification=NrhK1Hj7KuCPua1OcvfacDawt46H9VjByS4IAw5vsFA\\""
[4] "\\"v=spf1 include:pp._spf.paypal.com include:3rdparty._spf.paypal.com include:3rdparty1._spf.paypal.com include:3rdparty2._spf.paypal.com include:3rdparty3._spf.paypal.com include:c._spf.ebay.com ~all\\""
}

