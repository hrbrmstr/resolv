\name{resolv_a}
\alias{resolv_a}
\title{Returns the DNS A records for a given FQDN}
\usage{
resolv_a(fqdn, nameserver = NA_character_)
}
\arguments{
  \item{fqdn}{input character vector (FQDN)}

  \item{nameserver}{the nameserver to send the request to
  (optional; uses standard resolver behavior if not
  specified)}
}
\value{
vector of A records or \code{NULL} if none
}
\description{
Returns the DNS A records for a given FQDN
}
\examples{
require(resolv)
}
\seealso{
\url{http://www.nlnetlabs.nl/projects/ldns/}

\url{http://www.cambus.net/interesting-dns-hacks/} (cool
DNS A hacks vla
\url{https://twitter.com/habbie/status/460067198586081280})

Other ldns: \code{\link{resolv_cname}};
\code{\link{resolv_mx}}; \code{\link{resolv_ptr}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}}

Other resolv: \code{\link{resolv_cname}};
\code{\link{resolv_mx}}; \code{\link{resolv_ptr}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}}
}

