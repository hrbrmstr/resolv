\name{resolv_cname}
\alias{resolv_cname}
\title{Returns the DNS CNAME records for a given FQDN}
\usage{
resolv_cname(fqdn, nameserver = NA_character_)
}
\arguments{
  \item{fqdn}{input character vector (FQDN)}

  \item{nameserver}{the nameserver to send the request to
  (optional; uses standard resolver behavior if not
  specified)}
}
\value{
vector of CNAME records or \code{NULL} if none
}
\description{
Returns the DNS CNAME records for a given FQDN
}
\examples{
require(resolv)
}
\seealso{
\url{http://www.nlnetlabs.nl/projects/ldns/}

\url{http://www.cambus.net/interesting-dns-hacks/}

Other ldns: \code{\link{resolv_a}};
\code{\link{resolv_mx}}; \code{\link{resolv_ptr}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}}

Other resolv: \code{\link{asninfo}}; \code{\link{dnscalc}};
\code{\link{ip2asn}}; \code{\link{resolv_a}};
\code{\link{resolv_mx}}; \code{\link{resolv_ptr}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}};
\code{\link{wikidns}}
}

