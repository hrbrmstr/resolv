#' Vectorized version of \link{resolv_a}
#' 
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list
#' @export
A <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_a, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(f) { resolv_a(f, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_txt}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list
#' @export
TXT <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_txt, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(fqdn) { resolv_txt(fqdn, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_mx}
#'
#' @param fqdn input character vector (domain name)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return named vector or list 
#' @export
MX <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_mx, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(fqdn) { resolv_mx(fqdn, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_cname}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
CNAME <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_cname, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(fqdn) { resolv_cname(fqdn, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_ns}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
NS <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_ns, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(fqdn) { resolv_ns(fqdn, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_ptr}
#'
#' @param ip address input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
PTR <- function(ip, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(ip, resolv_ptr, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(ip, function(ip) { resolv_ptr(ip, nameserver, showWarnings, full) }))
  }
  
}

#' Vectorized version of \link{resolv_srv}
#'
#' @param fqdn input character vector (FQDN)
#' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
#' @param showWarnings display R warning messages (bool)
#' @param full include full record response information in results (bool)
#' @return list
#' @export
SRV <- function(fqdn, nameserver=NA_character_, showWarnings=FALSE, full=FALSE) {
  
  if (full) {
    return(Reduce(rbind, lapply(fqdn, resolv_srv, nameserver=nameserver, showWarnings=showWarnings, full=full)))
  } else {
    return(sapply(fqdn, function(fqdn) { resolv_srv(fqdn, nameserver, showWarnings, full) }))
  }
  
}

#' Return ASN info from Team CYNRU DNS lookup service
#' 
#' Pretty much provided as an example of data services. You
#' should use the one in the \link[iptools]{iptools} or \link[netintel]{netintel} packages
#' if you are serious about doing IP/ASN lookups.
#' 
#' @param ip address to lookup (character vector)
#' @return data frame containing named ASN attributes
#' @export
ip2asn <- function(ip="216.90.108.31") {
  
  Reduce(rbind.fill, lapply(ip, function(ip) {
    
    orig <- ip
    
    ip <- paste(paste(rev(unlist(strsplit(ip, "\\."))), sep="", collapse="."), 
                ".origin.asn.cymru.com", sep="", collapse="")
    result <- resolv_txt(ip)
    if (length(result) == 0) {
      return(data.frame(ip=orig, asn=NA, cidr=NA, cn=NA, registry=NA, regdate=NA))
    }
    out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
    
    return(data.frame(ip=orig, asn=out[1], cidr=out[2], cn=out[3], registry=out[4], regdate=out[5]))
    
  }))
  
}

#' Return ASN info from Team CYNRU DNS lookup service
#' 
#' @param asn number (with or without "AS" prefixed) to lookup (character vector)
#' @return data frame containing named ASN attributes
#' @export
asninfo <- function(asn="AS23028") {

  Reduce(rbind.fill, lapply(asn, function(asn) {
    
    orig <- asn
    
    # prefix with "AS" in case it isn't
    asn <- gsub("^([0-9]+)", "AS\\1", asn)
    asn <- paste(asn, ".asn.cymru.com", sep="", collapse="")
    result <- resolv_txt(asn)
    if (length(result) == 0) {
      return(data.frame(asn=orig, cn=NA, registry=NA, regdate=NA, location=NA))
    }
    out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
    
    return(data.frame(asn=out[1], cn=out[2], registry=out[3], regdate=out[4], location=out[5]))
    
  }))
  
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

#' @title Alexa Top 1 Million Sites
#' @description Alexa Top 1 Million Sites
#' \itemize{
#'   \item \code{rank}. rank of the domain (int)
#'   \item \code{domain}. the domain name (chr)
#' }
#'
#' @docType data
#' @keywords datasets
#' @name alexa
#' @seealso \itemize{
#'   \item IANA - \url{http://aws.amazon.com/alexa-top-sites/}
#' }
#' @usage data(alexa)
#' @note Last updated 2014-08-09
#' @format A data frame with 1000024 rows and 2 variables
NULL
