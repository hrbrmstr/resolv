// This file was generated by Rcpp::compileAttributes
// Generator token: 10BE3573-1514-4C36-9D1C-5A225CD40393

#include <Rcpp.h>

using namespace Rcpp;

// resolv_a
SEXP resolv_a(std::string fqdn, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_a(SEXP fqdnSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type fqdn(fqdnSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_a(fqdn, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_txt
SEXP resolv_txt(std::string fqdn, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_txt(SEXP fqdnSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type fqdn(fqdnSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_txt(fqdn, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_mx
SEXP resolv_mx(std::string domain, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_mx(SEXP domainSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type domain(domainSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_mx(domain, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_cname
SEXP resolv_cname(std::string fqdn, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_cname(SEXP fqdnSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type fqdn(fqdnSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_cname(fqdn, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_ns
SEXP resolv_ns(std::string fqdn, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_ns(SEXP fqdnSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type fqdn(fqdnSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_ns(fqdn, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_ptr
SEXP resolv_ptr(std::string ip, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_ptr(SEXP ipSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type ip(ipSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_ptr(ip, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
// resolv_srv
SEXP resolv_srv(std::string fqdn, SEXP nameserver = NA_STRING, bool showWarnings = false, bool full = false);
RcppExport SEXP resolv_resolv_srv(SEXP fqdnSEXP, SEXP nameserverSEXP, SEXP showWarningsSEXP, SEXP fullSEXP) {
BEGIN_RCPP
    SEXP __sexp_result;
    {
        Rcpp::RNGScope __rngScope;
        Rcpp::traits::input_parameter< std::string >::type fqdn(fqdnSEXP );
        Rcpp::traits::input_parameter< SEXP >::type nameserver(nameserverSEXP );
        Rcpp::traits::input_parameter< bool >::type showWarnings(showWarningsSEXP );
        Rcpp::traits::input_parameter< bool >::type full(fullSEXP );
        SEXP __result = resolv_srv(fqdn, nameserver, showWarnings, full);
        PROTECT(__sexp_result = Rcpp::wrap(__result));
    }
    UNPROTECT(1);
    return __sexp_result;
END_RCPP
}
