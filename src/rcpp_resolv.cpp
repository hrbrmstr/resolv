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

// TODO: make a header file
ldns_resolver *setresolver(const char *ns);
ldns_rdf *nshosttoaddr(ldns_resolver *res, const char *hostname);
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);

using namespace Rcpp;

// TODO: functions for more record types
// TODO: make a "dig"-like function that returns ALL THE THINGS

//' Returns the DNS A records for a given FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return vector or data frame (if \code{full}==\code{TRUE}) of A records or \code{character(0)} if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/} (cool DNS A hacks vla \url{https://twitter.com/habbie/status/460067198586081280})
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//' 
//' ## single address return
//' resolv_a("etsy.com")
//' [1] "38.106.64.123"
//' 
//' ## multiple address returns
//' resolv_a("google.com")
//' [1] "173.194.43.0"  "173.194.43.1"  "173.194.43.2"  "173.194.43.3" 
//' [5] "173.194.43.4"  "173.194.43.5"  "173.194.43.6"  "173.194.43.7" 
//' [9] "173.194.43.8"  "173.194.43.9"  "173.194.43.14"
//' 
//' ## must put at least one DNS hack in
//' resolv_a("10.15.add.calc.postel.org", "dns.postel.org")
//' [1] "0.25.0.0"
//' }
//[[Rcpp::export]]
SEXP resolv_a(std::string fqdn, SEXP nameserver = NA_STRING, 
              bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *a = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  char *answer_str ;
  
  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(fqdn.c_str());
  if (!domain) { return(CharacterVector(0)) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("address")=CharacterVector::create(NA_STRING),
                                      Named("owner")=CharacterVector::create(NA_STRING),
                                      Named("class")=NumericVector::create(NA_REAL),
                                      Named("ttl")=NumericVector::create(NA_REAL));
  
  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { 
    if(showWarnings) { Rf_warning("Could not process query") ; }; 
    ldns_resolver_deep_free(res);
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // get the A record(s)
  a = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER); 
  if (!a) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(a);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No A records");};
    if (full) return(empty); else return(CharacterVector(0)) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(a); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(a) ;
  CharacterVector results(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
  
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(a, i) ;
    // get data & convert to char
    answer_str = ldns_rdf2str(ldns_rr_a_address(answer) ) ;
    // add to vector
    results[i] = answer_str ;
    
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
    // clean up
    free(answer_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(a);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the A answer vector or data frame

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("address")=results,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(results);
  }
    
}

//' Returns the DNS TXT records for a given FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return vector or data frame (if \code{full}==\code{TRUE}) of TXT records or \code{character(0)} if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/} (cool DNS TXT hacks vla \url{https://twitter.com/habbie/status/460067198586081280})
//' @export
//' @examples
//' \dontrun{
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
//' ## seekrit URLs
//' browseURL(gsub("\"", "", resolv_txt("google-public-dns-a.google.com")))
//' 
//' ## get the TXT records for PayPal
//' resolv_txt("paypal.com")
//' [1] "\"MS=ms96239109\""                                                                                                                                                                                        
//' [2] "\"yandex-verification: 73acb90f6a9abd76\""                                                                                                                                                                
//' [3] "\"google-site-verification=NrhK1Hj7KuCPua1OcvfacDawt46H9VjByS4IAw5vsFA\""                                                                                                                                 
//' [4] "\"v=spf1 include:pp._spf.paypal.com include:3rdparty._spf.paypal.com include:3rdparty1._spf.paypal.com include:3rdparty2._spf.paypal.com include:3rdparty3._spf.paypal.com include:c._spf.ebay.com ~all\""
//' }
//[[Rcpp::export]]
SEXP resolv_txt(std::string fqdn, SEXP nameserver = NA_STRING, 
                           bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *txt = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  char *answer_str ;
  
  // we only passed in one value
  domain = ldns_dname_new_frm_str(fqdn.c_str());
  if (!domain) { if (full) return(DataFrame(0)); else return(CharacterVector(0)) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("txt")=CharacterVector::create(NA_STRING),
                                      Named("owner")=CharacterVector::create(NA_STRING),
                                      Named("class")=NumericVector::create(NA_REAL),
                                      Named("ttl")=NumericVector::create(NA_REAL));

  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) {
      ldns_rdf_deep_free(domain);
      if (full) return(empty); else return(CharacterVector(0)) ;
    }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { 
      ldns_rdf_deep_free(domain);
      if (full) return(empty); else return(CharacterVector(0)) ;
    }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_TXT, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) {
    if(showWarnings){Rf_warning("Could not process query");};
    ldns_resolver_deep_free(res);
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // get the TXT record(s)
  txt = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TXT, LDNS_SECTION_ANSWER); 
  if (!txt) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(txt);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No TXT records") ;};
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // sorting makes the results seem less "random"
  ldns_rr_list_sort(txt); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(txt) ;
  CharacterVector results(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
    
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(txt, i) ;
    // get data & convert to char
    answer_str = ldns_rdf2str(ldns_rr_rdf(answer, 0)) ;
    // add to vector
    results[i] = answer_str ;
    
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
    // clean up
    free(answer_str) ;
  }
    
  // clean up 
  ldns_rr_list_deep_free(txt);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the TXT answer vector

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("txt")=results,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(results);
  }
    
}

//' Returns the DNS MX records for a given domain
//'
//' @param fqdn input character vector (domain name)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return data frame of MX records (preference & exchange; +owner,class,ttl if \code{full}==\code{TRUE}) or an empty data frame if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/} (cool DNS MX hacks vla \url{https://twitter.com/habbie/status/460067198586081280})
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//' 
//' resolv_mx("rudis.net", full=TRUE)
//' ##        fqdn prefernece                 exchange      owner class ttl
//' ## 1 rudis.net          1      aspmx.l.google.com. rudis.net.     1 599
//' ## 2 rudis.net          5 alt1.aspmx.l.google.com. rudis.net.     1 599
//' ## 3 rudis.net          5 alt2.aspmx.l.google.com. rudis.net.     1 599
//' ## 4 rudis.net         10   aspmx2.googlemail.com. rudis.net.     1 599
//' ## 5 rudis.net         10   aspmx3.googlemail.com. rudis.net.     1 599
//' ## 6 rudis.net         10   aspmx4.googlemail.com. rudis.net.     1 599
//' ## 7 rudis.net         10   aspmx5.googlemail.com. rudis.net.     1 599
//' ## 8 rudis.net        100  mx-caprica.easydns.com. rudis.net.     1 599
//' }
//[[Rcpp::export]]
SEXP resolv_mx(std::string fqdn, SEXP nameserver = NA_STRING, 
               bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *dname = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *mx = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  char *answer_str, *pref_str ;
  
  // we only passed in one IP address
  dname = ldns_dname_new_frm_str(fqdn.c_str());
  if (!dname) { return(DataFrame()) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("prefernece")=CharacterVector::create(NA_STRING),
                                      Named("exchange")=CharacterVector::create(NA_STRING));
  
  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { ldns_rdf_deep_free(dname); return(empty) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { ldns_rdf_deep_free(dname); return(empty) ; }
    
  }
  
  p = ldns_resolver_query(res, dname, LDNS_RR_TYPE_MX, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(dname); // no longer needed
  
  if (!p) { 
    if(showWarnings){Rf_warning("Could not process query");}; 
    ldns_resolver_deep_free(res);
    return(empty) ; 
  }

  // get the MX record(s)
  mx = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_MX, LDNS_SECTION_ANSWER); 
  if (!mx) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(mx);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No MX records") ;};
    return(empty) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(mx); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(mx) ;
  CharacterVector prefs(nr) ;
  CharacterVector exch(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
 
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(mx, i) ;
    // get data & convert to char
    answer_str = ldns_rdf2str(ldns_rr_mx_exchange(answer)) ;
    pref_str = ldns_rdf2str(ldns_rr_mx_preference (answer)) ;
    
    prefs[i] = pref_str ;
    exch[i] = answer_str ;
    
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }

    // clean up
    free(answer_str) ;
    free(pref_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(mx);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the MX answer data frame

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("prefernece")=prefs,
                             Named("exchange")=exch,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("prefernece")=prefs,
                             Named("exchange")=exch));
  }
    
}

//' Returns the DNS CNAME records for a given FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return vector or data frame (if \code{full}==\code{TRUE}) of CNAME records or \code{character(0)} if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/}
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//'
//' resolv_cname("www.paypal.com")
//' [1] "www.paypal.com.akadns.net."
//' }
// [[Rcpp::export]]
SEXP resolv_cname(std::string fqdn, SEXP nameserver = NA_STRING,
                             bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *cname = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  ldns_rdf *rd ;
  char *answer_str ;
    
  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(fqdn.c_str());
  if (!domain) { if (full) return(DataFrame(0)); else return(CharacterVector(0)) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("cname")=CharacterVector::create(NA_STRING),
                                      Named("owner")=CharacterVector::create(NA_STRING),
                                      Named("class")=NumericVector::create(NA_REAL),
                                      Named("ttl")=NumericVector::create(NA_REAL));
  
  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { 
      ldns_rdf_deep_free(domain);
      if (full) return(empty); else return(CharacterVector(0)) ;
    }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { 
      ldns_rdf_deep_free(domain); 
      if (full) return(empty); else return(CharacterVector(0)) ;
    }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_CNAME, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { 
    if(showWarnings){Rf_warning("Could not process query") ;}; 
    ldns_resolver_deep_free(res);
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // get the CNAME record(s)
  cname = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_CNAME, LDNS_SECTION_ANSWER); 
  if (!cname) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(cname);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No CNAME records") ;};
    if (full) return(empty); else return(CharacterVector(0)) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(cname); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(cname) ;
  CharacterVector results(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
  
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(cname, i) ;
    // get data
    rd = ldns_rr_rdf(answer, 0) ;
    // convert to char
    answer_str = ldns_rdf2str(rd) ;
    // add to vector
    results[i] = answer_str ;
     
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
   // clean up
    free(answer_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(cname);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the CNAME answer vector

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("cname")=results,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(results);
  }    
}


//' Returns the DNS NS records for a given FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return vector or data frame (if \code{full}==\code{TRUE}) of NS records or \code{character(0)} if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/}
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//'
//' resolv_ns("www.paypal.com")
//' }
// [[Rcpp::export]]
SEXP resolv_ns(std::string fqdn, SEXP nameserver = NA_STRING,
                             bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *nsl = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  ldns_rdf *rd ;
  char *answer_str ;
  
  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(fqdn.c_str());
  if (!domain) { if (full) return(DataFrame(0)); else return(CharacterVector(0)) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("ns")=CharacterVector::create(NA_STRING),
                                      Named("owner")=CharacterVector::create(NA_STRING),
                                      Named("class")=NumericVector::create(NA_REAL),
                                      Named("ttl")=NumericVector::create(NA_REAL));

  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_NS, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { 
    if(showWarnings){Rf_warning("Could not process query") ;}; 
    ldns_resolver_deep_free(res);
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // get the NS record(s)
  nsl = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_NS, LDNS_SECTION_ANSWER); 
  if (!nsl) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(nsl);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No NS records") ;};
    if (full) return(empty); else return(CharacterVector(0)) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(nsl); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(nsl) ;
  CharacterVector results(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
  
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(nsl, i) ;
    // get data
    rd = ldns_rr_rdf(answer, 0) ;
    // convert to char
    answer_str = ldns_rdf2str(rd) ;
    // add to vector
    results[i] = answer_str ;
     
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
   // clean up
    free(answer_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(nsl);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the CNAME answer vector

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("ns")=results,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(results);
  }    
}

// helper functions to split a string
// via http://stackoverflow.com/a/236803/1457051

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
      elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

//' Returns the DNS PTR records for a given IP address
//'
//' @param ip address input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return vector or data frame (if \code{full}==\code{TRUE}) of PTR records or \code{character(0)} if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/}
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//'
//' # where www.nasa.gov hosts
//' resolv_a("www.nasa.gov")
//' [1] "69.28.187.45"    "208.111.161.110"
//' 
//' resolv_ptr("69.28.187.45")
//' [1] "cds355.iad.llnw.net."
//' 
//' ## big one - truncated output
//' resolv_ptr("17.149.160.49")
//'   [1] "asto.re."                   "next.com."                 
//'   [3] "qtml.com."                  "qttv.net."                 
//'   [5] "apple.com."                 "apple.info."               
//'   [7] "ikids.com."                 "qt-tv.net."                
//'   [9] "carbon.com."                "eworld.com."
//' ...  
//' [131] "quicktimestreaming.net."    "publishing-research.com."  
//' [133] "publishing-research.org."   "applefinalcutproworld.com."
//' [135] "applefinalcutproworld.net." "applefinalcutproworld.org."
//' }
//[[Rcpp::export]]
SEXP resolv_ptr(std::string ip, SEXP nameserver = NA_STRING, 
                           bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *ptr = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  char *answer_str ;
  
  std::vector<std::string> octets = split(ip, '.');
  std::string rev = octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa." ;
 
  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(rev.c_str());
  if (!domain) { if (full) return(DataFrame(0)); else return(CharacterVector(0)) ; }
  
  DataFrame empty = DataFrame::create(Named("ip")=ip,
                                      Named("ptr")=CharacterVector::create(NA_STRING),
                                      Named("owner")=CharacterVector::create(NA_STRING),
                                      Named("class")=NumericVector::create(NA_REAL),
                                      Named("ttl")=NumericVector::create(NA_REAL));
  
  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { ldns_rdf_deep_free(domain); if (full) return(empty); else return(CharacterVector(0)) ; }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { 
    if(showWarnings){Rf_warning("Could not process query");}; 
    ldns_resolver_deep_free(res);
    if (full) return(empty); else return(CharacterVector(0)) ;
  }

  // get the PTR record(s)
  ptr = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_PTR, LDNS_SECTION_ANSWER); 
  if (!ptr) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(ptr);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No PTR records");};
    if (full) return(empty); else return(CharacterVector(0)) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(ptr); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(ptr) ;
  CharacterVector results(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
  
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(ptr, i) ;
    // get data & convert to char
    answer_str = ldns_rdf2str(ldns_rr_rdf(answer, 0) ) ;
    // add to vector
    results[i] = answer_str ;
    
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
    // clean up
    free(answer_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(ptr);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the PTR answer vector
  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(ip),
                             Named("ptr")=results,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(results);
  }    
}

//' Returns the DNS SRV records for a given FQDN
//'
//' @param fqdn input character vector (FQDN)
//' @param nameserver the nameserver to send the request to (optional; uses standard resolver behavior if not specified)
//' @param showWarnings display R warning messages (bool)
//' @param full include full record response information in results (bool)
//' @return data frame of SRV records (named fields; +owner,class,ttl if \code{full}==\code{TRUE}) or an empty list if none
//' @seealso \url{http://www.nlnetlabs.nl/projects/ldns/}
//' @seealso \url{http://www.cambus.net/interesting-dns-hacks/}
//' @export
//' @examples
//' \dontrun{
//' require(resolv)
//' library(plyr)
//' 
//' ## google talk provides a good example for this
//' resolv_srv("_xmpp-server._tcp.gmail.com.", full=TRUE)
//' ##                           fqdn priority weight port                         target                        owner class ttl
//' ## 1 _xmpp-server._tcp.gmail.com.        5      0 5269      xmpp-server.l.google.com. _xmpp-server._tcp.gmail.com.     1 804
//' ## 2 _xmpp-server._tcp.gmail.com.       20      0 5269 alt1.xmpp-server.l.google.com. _xmpp-server._tcp.gmail.com.     1 804
//' ## 3 _xmpp-server._tcp.gmail.com.       20      0 5269 alt2.xmpp-server.l.google.com. _xmpp-server._tcp.gmail.com.     1 804
//' ## 4 _xmpp-server._tcp.gmail.com.       20      0 5269 alt3.xmpp-server.l.google.com. _xmpp-server._tcp.gmail.com.     1 804
//' ## 5 _xmpp-server._tcp.gmail.com.       20      0 5269 alt4.xmpp-server.l.google.com. _xmpp-server._tcp.gmail.com.     1 804
//' }
//[[Rcpp::export]]
SEXP resolv_srv(std::string fqdn, SEXP nameserver = NA_STRING, 
                bool showWarnings=false, bool full=false) {
  
  ldns_resolver *res = NULL;
  ldns_rdf *domain = NULL;
  ldns_pkt *p = NULL;
  ldns_rr_list *srv = NULL;
  ldns_status s;
  
  ldns_rr *answer;
  ldns_rdf *rd ;
  ldns_rdf *weight ;
  ldns_rdf *port ;
  ldns_rdf *target ;
  char *answer_str ;
  char *weight_str ;
  char *port_str ;
  char *target_str ;
  
  // we only passed in one IP address
  domain = ldns_dname_new_frm_str(fqdn.c_str());
  if (!domain) { return(DataFrame()) ; }
  
  DataFrame empty = DataFrame::create(Named("fqdn")=fqdn,
                                      Named("priority")=CharacterVector::create(NA_STRING),
                                      Named("weight")=CharacterVector::create(NA_STRING),
                                      Named("port")=CharacterVector::create(NA_STRING),
                                      Named("target")=CharacterVector::create(NA_STRING),
                                      Named("srv")=CharacterVector::create(NA_STRING),
                                      Named("srv")=CharacterVector::create(NA_STRING));

  std::string ns = as<std::string>(nameserver);
  
  if (ns != "NA") {
    
    res = setresolver(ns.c_str()) ;
    if (res == NULL ) { ldns_rdf_deep_free(domain); return(empty) ; }
    
  } else {
    
    s = ldns_resolver_new_frm_file(&res, NULL);
    if (s != LDNS_STATUS_OK) { ldns_rdf_deep_free(domain); return(empty) ; }
    
  }
  
  p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_ANY, LDNS_RR_CLASS_IN, LDNS_RD);
 
  ldns_rdf_deep_free(domain); // no longer needed
  
  if (!p) { 
    if(showWarnings){Rf_warning("Could not process query");}; 
    ldns_resolver_deep_free(res);
    return(empty) ; 
  }

  // get the SRV record(s)
  srv = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_SRV, LDNS_SECTION_ANSWER); 
  if (!srv) {
    ldns_pkt_free(p);
    ldns_rr_list_deep_free(srv);
    ldns_resolver_deep_free(res);
    if(showWarnings){Rf_warning("No SRV records");} ;
    return(empty) ;
  }
  
  // sorting makes the results seem less "random"
  ldns_rr_list_sort(srv); 
  
  // get the total # of records and make an R char vector of same length
  int nr = ldns_rr_list_rr_count(srv) ;
  List results(nr) ;
  CharacterVector rds(nr) ;
  CharacterVector weights(nr) ;
  CharacterVector ports(nr) ;
  CharacterVector targets(nr) ;
  CharacterVector owners(nr) ;
  NumericVector ttls(nr) ;
  NumericVector dnsclass(nr) ;
      
  // for each record, get the result as text and add to the vector
  for (int i=0; i<nr; i++) {
    // get record
    answer = ldns_rr_list_rr(srv, i) ;
    // get data
    rd = ldns_rr_rdf(answer, 0) ;
    weight = ldns_rr_rdf(answer, 1) ;
    port = ldns_rr_rdf(answer, 2) ;
    target = ldns_rr_rdf(answer, 3) ;
    // convert to char
    answer_str = ldns_rdf2str(rd) ;
    weight_str = ldns_rdf2str(weight) ;
    port_str = ldns_rdf2str(port) ;
    target_str = ldns_rdf2str(target) ;
    
    rds[i] = answer_str;
    weights[i] = weight_str;
    ports[i] = port_str;
    targets[i] = target_str;
    
    if (full) {
      owners[i] = ldns_rdf2str(ldns_rr_owner(answer) );
      ttls[i] = ldns_rr_ttl(answer);
      dnsclass[i] = ldns_rr_get_class(answer);
    }
    
    // clean up
    free(answer_str) ;
    free(weight_str) ;
    free(port_str) ;
    free(target_str) ;
  }
  
  // clean up 
  ldns_rr_list_deep_free(srv);  
  ldns_pkt_free(p);
  ldns_resolver_deep_free(res);
 
  // return the SRV answer vector

  if (full) {
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("priority")=rds,
                             Named("weight")=weights,
                             Named("port")=ports,
                             Named("target")=targets,
                             Named("owner")=owners,
                             Named("class")=dnsclass,
                             Named("ttl")=ttls));
  } else {  
    return(DataFrame::create(Named("fqdn")=CharacterVector::create(fqdn),
                             Named("priority")=rds,
                             Named("weight")=weights,
                             Named("port")=ports,
                             Named("target")=targets));
  }    
}

// host/IP \code{ldns_rdf} populated address
// 
// nshosttoaddr
// Ionically, a helper function to lookup an IP address for a hostname
// specifically when a \code{nameserver} parameter is specified
// in the exported functions and it's a FQDN vs an IP address.
// We pass in a \code{ldns_resolver} \code{res} structure so
// we can see if there's IPv6 support needed.
// 
// res an initialized \code{ldns_resolver} structure
// hostname FQDN we want to lookup
// \code{ldns_rdf} structure with the resolver set
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

// Create and populate \code{ldns} resolver
// 
// helper function to dset the resolver field since
// we need to do some extra work if not using the sytem
// defaults and actually specify a resolver to use
//
// ns the resolver FQDN or IP
// \code{ldns_resolver} structure
ldns_resolver *setresolver(const char *ns) {
  
  ldns_resolver *res = NULL ;
  
  res = ldns_resolver_new();
  
  ldns_rdf *addr = NULL;
  if ((addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ns)) == NULL) {
    addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, ns);
  }
  
  if (addr) {
    
    if (ldns_resolver_push_nameserver(res, addr) != LDNS_STATUS_OK) {
      Rf_warning("couldn't find nameserver address") ;
      return(NULL);
    }
    
  } else {
    
    addr = nshosttoaddr(res, ns) ;
    if (addr) {
      if (ldns_resolver_push_nameserver(res, addr) != LDNS_STATUS_OK) {
        Rf_warning("couldn't find nameserver address");
        return(NULL);
      }
    } else {
      Rf_warning("couldn't find nameserver address") ;
      return(NULL) ;
    }
  }
  
  return(res);
  
}

// IP address (binary) to string
// 
// helper function to turn an \code{sin[6]_addr} address into a string (IPv4 or IPv6)
// 
// sa \code{sockaddr} structure
// s pre-initialized buffer space for the string
// maxlen max size of \code{s}
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

  return s;
  
}
