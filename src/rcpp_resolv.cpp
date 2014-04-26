 
#include <Rcpp.h>
#include <Rinternals.h>
#include <Rdefines.h>
 
#ifdef __linux__
#include <bsd/string.h>
#endif
 
// REF: http://www.nlnetlabs.nl/projects/ldns/ for API info
#include <ldns/ldns.h>

using namespace Rcpp;

//' Returns the DNS TXT records for a FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @return vector of TXT records or \code{NULL} if none
//' @export
//' @examples
//' require(resolv)
//' 
//' ## get the TXT record for Google
//' resolv_txt("google.com")
//' [1] "\"v=spf1 include:_spf.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all\""
//' 
//' ## get the TXT records for PayPal
//' resolv_txt("paypal.com")
//' [1] "\"MS=ms96239109\""                                                                                                                                                                                        
//' [2] "\"yandex-verification: 73acb90f6a9abd76\""                                                                                                                                                                
//' [3] "\"google-site-verification=NrhK1Hj7KuCPua1OcvfacDawt46H9VjByS4IAw5vsFA\""                                                                                                                                 
//' [4] "\"v=spf1 include:pp._spf.paypal.com include:3rdparty._spf.paypal.com include:3rdparty1._spf.paypal.com include:3rdparty2._spf.paypal.com include:3rdparty3._spf.paypal.com include:c._spf.ebay.com ~all\""
// [[Rcpp::export]]
SEXP resolv_txt(SEXP fqdn) {
  
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

  s = ldns_resolver_new_frm_file(&res, NULL);
  if (s != LDNS_STATUS_OK) { return(R_NilValue) ; }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { return(R_NilValue) ; }

  // get the TXT record(s)
  txt = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER); 
  if (!txt) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(txt);
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
