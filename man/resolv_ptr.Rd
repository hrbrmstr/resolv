\name{resolv_ptr}
\alias{resolv_ptr}
\title{Returns the DNS PTR records for a given IP address}
\usage{
resolv_ptr(ip, nameserver = NA_character_)
}
\arguments{
  \item{IP}{address input character vector (FQDN)}

  \item{nameserver}{the nameserver to send the request to
  (optional; uses standard resolver behavior if not
  specified)}
}
\value{
vector of PTR records or \code{NULL} if none
}
\description{
Returns the DNS PTR records for a given IP address
}
\examples{
require(resolv)
}
\seealso{
\url{http://www.nlnetlabs.nl/projects/ldns/}

\url{http://www.cambus.net/interesting-dns-hacks/}

Other ldns: \code{\link{resolv_a}};
\code{\link{resolv_cname}}; \code{\link{resolv_mx}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}}

Other resolv: \code{\link{resolv_a}};
\code{\link{resolv_cname}}; \code{\link{resolv_mx}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}}
}

