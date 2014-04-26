#' Return ASN info from Team CYNRU DNS lookup service
#' @param IP address to lookup (character vector)
#' @return list containing named ASN attributes
#
ip2asn <- function(ip="216.90.108.31") {

  orig <- ip
  
  ip <- paste(paste(rev(unlist(strsplit(ip, "\\."))), sep="", collapse="."), 
              ".origin.asn.cymru.com", sep="", collapse="")
  
  result <- resolv_txt(as.character(ip))
  
  out <- unlist(strsplit(gsub("\"", "", result), "\ *\\|\ *"))
  
  return(list(ip=orig, asn=out[1], cidr=out[2], cn=out[3], registry=out[4]))
  
}
