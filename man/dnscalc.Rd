\name{dnscalc}
\alias{dnscalc}
\title{Return simple math computations via DNS}
\usage{
dnscalc(a = 0:99, b = 0:99, op = c("add", "sub", "mul", "div"))
}
\arguments{
  \item{a}{first number (0-99)}

  \item{b}{second number (0-99)}

  \item{op}{calculation to perform (add|sub|mul|div)}
}
\value{
result (in IP address octet notation)
}
\description{
Return simple math computations via DNS
}
\seealso{
http://www.isi.edu/touch/tools/dns-calc.html

Other resolv: \code{\link{asninfo}}; \code{\link{ip2asn}};
\code{\link{resolv_a}}; \code{\link{resolv_cname}};
\code{\link{resolv_mx}}; \code{\link{resolv_ptr}};
\code{\link{resolv_srv}}; \code{\link{resolv_txt}};
\code{\link{wikidns}}
}

