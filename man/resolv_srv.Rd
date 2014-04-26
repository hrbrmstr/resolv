\name{resolv_srv}
\alias{resolv_srv}
\title{Returns the DNS SRV records for a given FQDN}
\usage{
resolv_srv(fqdn, nameserver = NA_character_)
}
\arguments{
  \item{fqdn}{input character vector (FQDN)}

  \item{nameserver}{the nameserver to send the request to
  (optional; uses standard resolver behavior if not
  specified)}
}
\value{
list of SRV records (named fields) or \code{NULL} if none
}
\description{
Returns the DNS SRV records for a given FQDN
}
\examples{
require(resolv)
}
\seealso{
\url{http://www.nlnetlabs.nl/projects/ldns/}

\url{http://www.cambus.net/interesting-dns-hacks/}

Other ldns: \code{\link{resolv_cname}};
\code{\link{resolv_mx}}; \code{\link{resolv_txt}}

Other resolv: \code{\link{resolv_cname}};
\code{\link{resolv_mx}}; \code{\link{resolv_txt}}
}

