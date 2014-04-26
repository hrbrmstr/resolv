#' Return ASN info from Team CYNRU DNS lookup service
#' @param IP address to lookup (character vector)
#' @return list containing named ASN attributes
#' @export
#
ip2asn <- function(ip="216.90.108.31") {

  orig <- ip
  
  ip <- paste(paste(rev(unlist(strsplit(ip, "\\."))), sep="", collapse="."), 
              ".origin.asn.cymru.com", sep="", collapse="")
  
  result <- resolv_txt(as.character(ip))
  
  out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
  
  return(list(ip=orig, asn=out[1], cidr=out[2], cn=out[3], registry=out[4], regdate=out[5]))
  
}

#' Return ASN info from Team CYNRU DNS lookup service
#' @param ASN number (with or without "AS" prefixed) to lookup (character vector)
#' @return list containing named ASN attributes
#' @export
#
asninfo <- function(asn="AS23028") {
  
  orig <- asn
  
  # prefix with "AS" in case it isn't
  asn <- gsub("^([0-9]+)", "AS\\1", asn)
  
  asn <- paste(asn, ".asn.cymru.com", sep="", collapse="")
  
  result <- resolv_txt(as.character(asn))
  
  out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
  
  return(list(asn=out[1], cn=out[1], registry=out[2], regdate=out[3], locaton=out[4]))
  
}
