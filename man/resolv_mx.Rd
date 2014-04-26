\name{resolv_mx}
\alias{resolv_mx}
\title{Returns the DNS MX records for a given domain}
\usage{
resolv_mx(domain, nameserver = NA_character_)
}
\arguments{
  \item{domain}{input character vector (domain name)}

  \item{nameserver}{the nameserver to send the request to
  (optional; uses standard resolver behavior if not
  specified)}
}
\value{
vector of MX records or \code{NULL} if none
}
\description{
Returns the DNS MX records for a given domain
}
\examples{
require(resolv)

## get the MX record for Google
resolv_mx("google.com")
}
\seealso{
\url{http://www.nlnetlabs.nl/projects/ldns/}

\url{http://www.cambus.net/interesting-dns-hacks/} (cool
DNS MX hacks vla
\url{https://twitter.com/habbie/status/460067198586081280})

Other ldns: \code{\link{resolv_txt}}

Other resolv: \code{\link{resolv_txt}}
}

