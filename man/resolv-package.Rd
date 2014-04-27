\name{resolv-package}
\alias{resolv-package}
\alias{resolv}
\docType{package}
\title{
Wrapper to the \code{ldns} DNS resolver library
}
\description{
Provides functions to perform robust DNS lookups from R.
Uses the \code{ldns} library which provides support for IPv4 & IPv6 addresses
as well as DNSSEC.
}
\details{
\tabular{ll}{
Version: \tab 0.1\cr
Depends: \tab R Rcpp\cr
Suggests: \tab plyr\cr
Package: \tab resolv\cr
Type: \tab Package\cr
Date: \tab 2014-04-26\cr
BugReports: \tab \url{https://github.com/hrbrmstr/resolv}\cr
License: \tab MIT\cr
URL: \tab \url{https://github.com/hrbrmstr/resolv}\cr
NeedsCompilation: \tab yes\cr
}

Core functions:\cr\cr
\code{resolv_txt()} - perform TXT lookups\cr
\code{resolv_mx()} - perform MX lookups\cr
\code{resolv_cname()} - perform CNAME\cr
\code{resolv_srv()} - perform SRV lookups\cr
\code{resolv_a()} - perform SRV lookups\cr
\code{resolv_ptr()} - perform SRV lookups\cr

Ancillary "Fun"ctions:\cr\cr
\code{ip2asn()} - interface to http://www.team-cymru.org/Services/ip-to-asn.html#dns\cr
\code{asninfo()} - interface to http://www.team-cymru.org/Services/ip-to-asn.html#dns\cr
\code{wikidns()} - interface to https://dgl.cx/wikipedia-dns\cr
\code{dnscalc()} - interface to http://www.isi.edu/touch/tools/dns-calc.html\cr
}
\author{
boB Rudis (@hrbrmstr)

Maintainer: boB Rudis <bob@rudis.net>
}
\references{
\url{http://www.nlnetlabs.nl/projects/ldns/}
}
\keyword{ package }
\seealso{
\url{https://github.com/hrbrmstr/resolv}\cr
\url{http://www.nlnetlabs.nl/projects/ldns/}\cr
\url{http://dds.ec/blog/posts/2014/Apr/making-better-dns-txt-record-lookups-with-rcpp/}
}
\examples{
require(resolv)
library(plyr)

## google talk provides a good example for this
ldply(resolv_srv("_xmpp-server._tcp.gmail.com."), unlist)
priority weight port                         target
1        5      0 5269      xmpp-server.l.google.com.
2       20      0 5269 alt1.xmpp-server.l.google.com.
3       20      0 5269 alt2.xmpp-server.l.google.com.
4       20      0 5269 alt3.xmpp-server.l.google.com.
5       20      0 5269 alt4.xmpp-server.l.google.com.

# where www.nasa.gov hosts
resolv_a("www.nasa.gov")
[1] "69.28.187.45"    "208.111.161.110"

resolv_ptr("69.28.187.45")
[1] "cds355.iad.llnw.net."


}
