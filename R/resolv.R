#' Vectorized version of \link{resolv_a}
#' 
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list
#' @export
A <- Vectorize(resolv_a, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_txt}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list
#' @export
TXT <- Vectorize(resolv_txt, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_mx}
#'
#' @param domain input character vector (domain name)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list 
#' @export
MX <- Vectorize(resolv_mx, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_cname}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
CNAME <- Vectorize(resolv_cname, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_ns}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
NS <- Vectorize(resolv_ns, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_ptr}
#'
#' @param IP address input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
PTR <- Vectorize(resolv_ptr, SIMPLIFY=FALSE)

#' Vectorized version of \link{resolv_ptr}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
SRV <- Vectorize(resolv_srv, SIMPLIFY=FALSE)


#' Return ASN info from Team CYNRU DNS lookup service
#' 
#' @param ip address to lookup (character vector)
#' @return list containing named ASN attributes
#' @export
ip2asn <- function(ip="216.90.108.31") {

  orig <- ip
  
  ip <- paste(paste(rev(unlist(strsplit(ip, "\\."))), sep="", collapse="."), 
              ".origin.asn.cymru.com", sep="", collapse="")
  result <- resolv_txt(ip)
  out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
  
  return(list(ip=orig, asn=out[1], cidr=out[2], cn=out[3], registry=out[4], regdate=out[5]))
  
}

#' Return ASN info from Team CYNRU DNS lookup service
#' 
#' @param asn number (with or without "AS" prefixed) to lookup (character vector)
#' @return list containing named ASN attributes
#' @export
asninfo <- function(asn="AS23028") {
  
  orig <- asn
  
  # prefix with "AS" in case it isn't
  asn <- gsub("^([0-9]+)", "AS\\1", asn)
  asn <- paste(asn, ".asn.cymru.com", sep="", collapse="")
  result <- resolv_txt(asn)
  out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
  
  return(list(asn=out[1], cn=out[2], registry=out[3], regdate=out[4], location=out[5]))
  
}

#' Return wikipedia topic via DNS
#' 
#' @param term wikipedia term to lookup
#' @return vector of TXT record results for term description
#' @export
#' @seealso https://dgl.cx/wikipedia-dns
wikidns <- function(term="bayes") {
  term <- paste(term, ".wp.dg.cx", sep="", collapse="")
  return(resolv_txt(term))
  
}

#' Return simple math computations via DNS
#' 
#' @param a first number (0-99)
#' @param b second number (0-99)
#' @param op calculation to perform (add|sub|mul|div)
#' @return result (in IP address octet notation)
#' @export
#' @seealso http://www.isi.edu/touch/tools/dns-calc.html
dnscalc <- function(a=0:99, b=0:99, op=c("add", "sub", "mul", "div")) {
  op <- ifelse(op %in% c("add", "sub", "mul", "div"), op, "add")
  calc <- paste(a%%100, ".", b%%100, ".", op, ".calc.postel.org", sep="", collapse="")
  return(resolv_a(calc, "dns.postel.org"))
}

#' Wrapper to ldns library for DNS calls from R
#' @docType package
#' @name resolv-package
#' @aliases resolv
#' @author Bob Rudis <bob@@rudis.net>
#' @import Rcpp
#' @useDynLib resolv
#' @references \url{http://www.nlnetlabs.nl/projects/ldns/}
#' @seealso
#' \itemize{
#'   \item \url{https://github.com/hrbrmstr/resolv}
#'   \item \url{http://www.nlnetlabs.nl/projects/ldns/}
#'   \item \url{http://dds.ec/blog/posts/2014/Apr/making-better-dns-txt-record-lookups-with-rcpp/}
#' }
#' @examples
#' \dontrun{
#' require(resolv)
#' library(plyr)
#'
#' ## google talk provides a good example for this
#' resolv_srv("_xmpp-server._tcp.gmail.com.")
#' 
#' ##                           fqdn priority weight port                         target
#' ## 1 _xmpp-server._tcp.gmail.com.        5      0 5269      xmpp-server.l.google.com.
#' ## 2 _xmpp-server._tcp.gmail.com.       20      0 5269 alt1.xmpp-server.l.google.com.
#' ## 3 _xmpp-server._tcp.gmail.com.       20      0 5269 alt2.xmpp-server.l.google.com.
#' ## 4 _xmpp-server._tcp.gmail.com.       20      0 5269 alt3.xmpp-server.l.google.com.
#' ## 5 _xmpp-server._tcp.gmail.com.       20      0 5269 alt4.xmpp-server.l.google.com. 
#' 
#' ## where www.nasa.gov hosts
#' resolv_a("www.nasa.gov", full=TRUE)
#' 
#' ##           fqdn       address                owner class ttl
#' ## 1 www.nasa.gov 69.28.157.198 iznasa.hs.llnwd.net.     1 274
#'
#' resolv_ptr("69.28.187.45")
#' ## [1] "cds355.iad.llnw.net."
#' 
#' ## vectorized
#' A(c("dds.ec", "rud.is"), full=TRUE)
#' 
#' ## $dds.ec
#' ##     fqdn       address   owner class ttl
#' ## 1 dds.ec 162.243.111.4 dds.ec.     1  87
#' ## 
#' ## $rud.is
#' ##     fqdn        address   owner class   ttl
#' ## 1 rud.is 184.106.97.102 rud.is.     1 17781
#
#' # seekrit URLs
#' browseURL(gsub("\"", "", resolv_txt("google-public-dns-a.google.com")))
#'
#' }
NULL
