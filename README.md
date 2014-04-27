resolv
======

ldns DNS resolver wrapper libary for R

Needs `ldns` - http://www.nlnetlabs.nl/projects/ldns/ - which is `apt`-able and `brew`-able.

    library(devtools)
    install_github("hrbrmstr/resolv")

### Description

Provides functions to perform robust DNS lookups from R. Uses the `ldns` library which provides support for IPv4 & IPv6 addresses as well as DNSSEC. This library currently exposes the functions indicated below.

### Details

    Package: resolv
    Type:    Package
    Version: 0.1
    Date:    2014-04-26
    License: MIT


- `resolv_txt()` - perform TXT lookups
- `resolv_mx()` - perform MX lookups (returns list)
- `resolv_cname()` - perform CNAME lookups
- `resolv_srv()` - perform SRV lookups (returns list)
- `resolv_a()` - perform A lookups
- `resolv_ptr()` - perform SRV lookups

### Author(s)

   boB Rudis (@hrbrmstr)

   Maintainer: boB Rudis <bob@rudis.net>

### References

   http://www.nlnetlabs.nl/projects/ldns/

### See Also

- http://www.nlnetlabs.nl/projects/ldns/
- http://dds.ec/blog/posts/2014/Apr/making-better-dns-txt-record-lookups-with-rcpp/