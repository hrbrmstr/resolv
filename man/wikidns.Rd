\name{wikidns}
\alias{wikidns}
\title{Return wikipedia topic via DNS}
\usage{
wikidns(term = "bayes")
}
\arguments{
  \item{term}{wikipedia term to lookup}
}
\value{
vector of TXT record results for term description
}
\description{
Return wikipedia topic via DNS
}
\seealso{
https://dgl.cx/wikipedia-dns

Other resolv: \code{\link{asninfo}}; \code{\link{dnscalc}};
\code{\link{ip2asn}}; \code{\link{resolv_a}};
\code{\link{resolv_cname}}; \code{\link{resolv_mx}};
\code{\link{resolv_ptr}}; \code{\link{resolv_srv}};
\code{\link{resolv_txt}}
}

