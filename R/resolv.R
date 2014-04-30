#' Return ASN info from Team CYNRU DNS lookup service
#' 
#' @param ip address to lookup (character vector)
#' @return list containing named ASN attributes
#' @family resolv
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
#' @family resolv
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
#' @family resolv
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
#' @family resolv
#' @seealso http://www.isi.edu/touch/tools/dns-calc.html
dnscalc <- function(a=0:99, b=0:99, op=c("add", "sub", "mul", "div")) {
  op <- ifelse(op %in% c("add", "sub", "mul", "div"), op, "add")
  calc <- paste(a%%100, ".", b%%100, ".", op, ".calc.postel.org", sep="", collapse="")
  return(resolv_a(calc, "dns.postel.org"))
}
