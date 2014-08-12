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
#' ldply(resolv_srv("_xmpp-server._tcp.gmail.com."), unlist)
#' ## priority weight port                         target
#' ## 1        5      0 5269      xmpp-server.l.google.com.
#' ## 2       20      0 5269 alt1.xmpp-server.l.google.com.
#' ## 3       20      0 5269 alt2.xmpp-server.l.google.com.
#' ## 4       20      0 5269 alt3.xmpp-server.l.google.com.
#' ## 5       20      0 5269 alt4.xmpp-server.l.google.com.
#' 
#' where www.nasa.gov hosts
#' resolv_a("www.nasa.gov")
#' ## [1] "69.28.187.45"    "208.111.161.110"
#'
#' resolv_ptr("69.28.187.45")
#' ## [1] "cds355.iad.llnw.net."
#' 
#' # seekrit URLs
#' browseURL(gsub("\"", "", resolv_txt("google-public-dns-a.google.com")))
#'
#' }
NULL
