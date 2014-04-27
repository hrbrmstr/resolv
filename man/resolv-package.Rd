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
Package: \tab resolv\cr
Type: \tab Package\cr
Version: \tab 0.1\cr
Date: \tab 2014-04-26\cr
License: \tab MIT\cr
}
\code{resolv_txt()} - perform TXT lookups\cr
\code{resolv_mx()} - perform MX lookups\cr
\code{resolv_cname()} - perform CNAME\cr
\code{resolv_srv()} - perform SRV lookups\cr
\code{resolv_a()} - perform SRV lookups\cr
\code{resolv_ptr()} - perform SRV lookups\cr

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
\url{http://www.nlnetlabs.nl/projects/ldns/}\cr
\url{http://dds.ec/blog/posts/2014/Apr/making-better-dns-txt-record-lookups-with-rcpp/}
}
\examples{
%% ~~ simple examples of the most important functions ~~
}
