 
#include <Rcpp.h>
#include <Rinternals.h>
#include <Rdefines.h>
 
#ifdef __linux__
#include <bsd/string.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// REF: http://www.nlnetlabs.nl/projects/ldns/ for API info
#include <ldns/ldns.h>

ldns_resolver *setresolver(const char *ns);
ldns_rdf *nshosttoaddr(ldns_resolver *res, const char *hostname);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);

using namespace Rcpp;

//' Returns the DNS TXT records for a FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @return vector of TXT records or \code{NULL} if none
//' @family ldns
//' @family resolv
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/} (cool DNS TXT hacks vla \url{https://twitter.com/habbie/status/460067198586081280})
//' @export
//' @examples
//' require(resolv)
//' 
//' ## get the TXT record for Google
//' resolv_txt("google.com")
//' [1] "\"v=spf1 include:_spf.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all\""
//' 
//' ## Use Team CYMRU ASN TXT record lookup service
//' resolv_txt("31.108.90.216.origin.asn.cymru.com")
//' [1] "\"23028 | 216.90.108.0/24 | US | arin |\""
//'
//' ## Wikipedia lookups:
//' resolv_txt("bind.wp.dg.cx")
//' [1] "\"BIND , or named , is the most widely used DNS software on the Internet. On Unix-like operating systems it is the de facto standard. http://en.wikipedia.org/wiki/BIND\""
//'
//' ## get the TXT records for PayPal
//' resolv_txt("paypal.com")
//' [1] "\"MS=ms96239109\""                                                                                                                                                                                        
//' [2] "\"yandex-verification: 73acb90f6a9abd76\""                                                                                                                                                                
//' [3] "\"google-site-verification=NrhK1Hj7KuCPua1OcvfacDawt46H9VjByS4IAw5vsFA\""                                                                                                                                 
//' [4] "\"v=spf1 include:pp._spf.paypal.com include:3rdparty._spf.paypal.com include:3rdparty1._spf.paypal.com include:3rdparty2._spf.paypal.com include:3rdparty3._spf.paypal.com include:c._spf.ebay.com ~all\""
// [[Rcpp::export]]
SEXP resolv_txt(SEXP fqdn, SEXP nameserver = NA_STRING) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *txt = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  ldns_rdf *rd ;
  char *answer_str ;
  
  // SEXP passes in an R vector, we need this as a C++ string
  std::string fqdns = as<std::string>(fqdn);

  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(fqdns.c_str());
  if (!domain) { return(R_NilValue) ; }
  
  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { return(R_NilValue) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { return(R_NilValue) ; }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { Rcout << "Could not process query" << std::endl ; return(R_NilValue) ; }

  // get the TXT record(s)
  txt = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER); 
  if (!txt) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(txt);
    Rcout << "No TXT records" << std::endl ;
    return(R_NilValue) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(txt); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(txt) ;
  CharacterVector results(nr) ;
  
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(txt, i) ;
    // get data
    rd = ldns_rr_rdf(answer, 0) ;
    // convert to char
    answer_str = ldns_rdf2str(rd) ;
    // add to vector
    results[i] = answer_str ;
    // clean up
    free(answer_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(txt);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the TXT answer vector
  return(results);
    
}

ldns_resolver *setresolver(const char *ns) {
  
  ldns_resolver *res = NULL ;
  
  res = ldns_resolver_new();
  
  ldns_rdf *addr = NULL;
  if ((addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ns)) == NULL) {
    addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ns);
  }
  
  if (addr) {
    
    if (ldns_resolver_push_nameserver(res, addr) != LDNS_STATUS_OK) {
      Rcout << "couldn't find nameserver address" << std::endl ;
      return(NULL);
    }
    
  } else {
    
    addr = nshosttoaddr(res, ns) ;
    if (addr) {
      if (ldns_resolver_push_nameserver(res, addr) != LDNS_STATUS_OK) {
        Rcout << "couldn't find nameserver address" << std::endl ;
        return(NULL);
      }
    } else {
      Rcout << "couldn't find nameserver address" << std::endl ;
      return(NULL) ;
    }
  }
  
  return(res);
  
}

ldns_rdf *nshosttoaddr(ldns_resolver *res, const char *hostname) {
  
  struct addrinfo hints, *ailist;
  int err = 0;

  memset(&hints, 0, sizeof(hints));

  switch (ldns_resolver_ip6(res)) {
    case LDNS_RESOLV_INET: hints.ai_family = PF_INET; break;
    case LDNS_RESOLV_INET6: hints.ai_family = PF_INET6; break;
    default: hints.ai_family = PF_UNSPEC; break;
  }
  
  hints.ai_socktype = SOCK_STREAM;
  
  do {
    getaddrinfo(hostname, NULL, &hints, &ailist);
  } while (err == EAI_AGAIN);
  
  if(err == 0){
   
    char ip[40] ;
    ldns_rdf *addr = NULL;
    if ((addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, get_ip_str(ailist->ai_addr, ip, sizeof(ip)))) == NULL) {
      addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, get_ip_str(ailist->ai_addr, ip, sizeof(ip)));
    }
    return(addr) ;
    
  } else {
    return(NULL) ;    
  }
  
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
  
  switch(sa->sa_family) {
    case AF_INET:
    inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
    s, maxlen);
    break;
    
    case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
    s, maxlen);
    break;
    
    default:
    strncpy(s, "Unknown AF", maxlen);
    return NULL;
  }  
  Rcout << s << std::endl ;
  return s;
  
}
