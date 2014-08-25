[![DOI](https://zenodo.org/badge/5630/hrbrmstr/resolv.png)](http://dx.doi.org/10.5281/zenodo.11343)

resolv
======

ldns DNS resolver wrapper libary for R

Needs `ldns` - <http://www.nlnetlabs.nl/projects/ldns/> - which is `apt`-able and `brew`-able.

    library(devtools)
    install_github("hrbrmstr/resolv")

[These folks](http://dev.telnic.org/trac/wiki/DotTelUtils) seem to have done some work getting the `ldns` library to work under Windows, but this particular package only works (for now on Linux/Mac OS X.

Bug reports (esp from ppl with more C++/Rcpp experience), feature requests & pull requests welcome/encouraged. The code/package is documented pretty well (esp for me). Hopefully this library can replace `system` calls for folks who need to "do DNS stuff" from R.

### News

-   Version update to `0.2.2` includes making the parameters fully consistent, making the vectorized functions work better and having even saner return values when there were errors or no records found
-   Version update to `0.2.1` includes 2 memory fixes and better return types if no records are found
-   Version update to `0.2.0` includes ability to (optionally - set the `full` parameter to `TRUE`) return `class`, `ttl` & `owner` fields, includes `resolve_ns()` and `NS()` functions, plus changes return type for a few functions.
-   Version update to `0.1.2` after running `valgrind` and fixing some missing `free`'s (`#ty` to [@arj](<http://twitter.com/arj>)!)
-   Version update to `0.1.1` as I modified some of the roxygen documentation to better make this work out of the box. Any help getting it to work on Windows is greatly appreciated

### Description

Provides functions to perform robust DNS lookups from R. Uses the `ldns` library which provides support for IPv4 & IPv6 addresses as well as DNSSEC. This library currently exposes the functions indicated below.

### Details

    Package: resolv
    Type: Package
    Title: Wrapper to ldns library for DNS calls from R
    Version: 0.2.2
    Date: 2014-08-21
    Author: Bob Rudis (@hrbrmstr)
    Maintainer: Bob Rudids <bob@rudis.net>
    Description: Wrapper to ldns library for DNS calls from R. It provides
        vecorized & non-vectorized version of core DNS query functions and
        allows for vector or data frame return values in most functions
        (depending on the level of detail desired from the query). It's
        significantly faster than issuing a system() call but does not
        yet work under Windows.
    URL: https://github.com/hrbrmstr/resolv
    BugReports: https://github.com/hrbrmstr/resolv/issues
    License: GPL-2
    Imports:
        Rcpp (>= 0.11.1)
    LinkingTo: Rcpp

Direct `ldns` wrappers:

-   `resolv_txt()` - perform TXT lookups
-   `resolv_mx()` - perform MX lookups (returns data frame)
-   `resolv_cname()` - perform CNAME lookups
-   `resolv_srv()` - perform SRV lookups (returns data frame)
-   `resolv_a()` - perform A lookups
-   `resolv_ptr()` - perform PTR lookups
-   `resolv_ns()` - perform NS lookups

and, their vectorized counterparts:

-   `TXT()`
-   `MX()`
-   `CNAME()`
-   `SRV()`
-   `A()`
-   `PTR()`
-   `NS()`

(TODO: to add "SOA" suppot)

Ancillary/"fun"ctions

These show off some of what you can do with DNS

-   `ip2asn()` - interface to <http://www.team-cymru.org/Services/ip-to-asn.html#dns>
-   `asninfo()` - interface to <http://www.team-cymru.org/Services/ip-to-asn.html#dns>
-   `wikidns()` - interface to <https://dgl.cx/wikipedia-dns>
-   `dnscalc()` - interface to <http://www.isi.edu/touch/tools/dns-calc.html>

### Installation

``` {.r}
devtools::install_github("hrbrmstr/resolv")
```

> Don't forget the need to `brew install ldns` or your favorite linux pkg mgr equivalent, first.

### Usage

``` {.r}
require(resolv)
```

    ## Loading required package: resolv
    ## Loading required package: plyr

``` {.r}
library(plyr)

## google talk provides a good example for this
resolv_srv("_xmpp-server._tcp.gmail.com.")
```

    ##                           fqdn priority weight port                         target
    ## 1 _xmpp-server._tcp.gmail.com.        5      0 5269      xmpp-server.l.google.com.
    ## 2 _xmpp-server._tcp.gmail.com.       20      0 5269 alt1.xmpp-server.l.google.com.
    ## 3 _xmpp-server._tcp.gmail.com.       20      0 5269 alt2.xmpp-server.l.google.com.
    ## 4 _xmpp-server._tcp.gmail.com.       20      0 5269 alt3.xmpp-server.l.google.com.
    ## 5 _xmpp-server._tcp.gmail.com.       20      0 5269 alt4.xmpp-server.l.google.com.

``` {.r}
## where www.nasa.gov hosts
resolv_a("www.nasa.gov")
```

    ## [1] "69.28.157.198"

``` {.r}
## DNS seekrit TXT URLs
## uncomment and run it locally
# browseURL(gsub("\"", "", resolv_txt("google-public-dns-a.google.com")))

# vectorized + full return
TXT(c("stackoverflow.com", "microsoft.com", "apple.com", "google.com"), full=TRUE)
```

    ##                fqdn
    ## 1 stackoverflow.com
    ## 2     microsoft.com
    ## 3     microsoft.com
    ## 4         apple.com
    ## 5        google.com
    ##                                                                                                                                                                                                                                                          txt
    ## 1                                                                                                                                                      "v=spf1 a mx ip4:198.252.206.0/24 ip4:69.59.197.0/26 include:cmail1.com include:_spf.google.com ~all"
    ## 2                                                                                                                                                                 "FbUF6DbkE+Aw1/wi9xgDi8KVrIIZus5v8L6tbIQZkGrQ/rVQKJi8CjQbBtWtE64ey4NJJwj5J65PIggVYNabdQ=="
    ## 3 "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.microsoft.com include:spf-a.hotmail.com ip4:147.243.128.24 ip4:147.243.128.26 ip4:147.243.128.25 ip4:147.243.1.47 ip4:147.243.1.48 -all"
    ## 4                                                                                                                                                                                                                               "v=spf1 ip4:17.0.0.0/8 ~all"
    ## 5                                                                                                                                                                              "v=spf1 include:_spf.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all"
    ##                owner class  ttl
    ## 1 stackoverflow.com.     1  299
    ## 2     microsoft.com.     1 3097
    ## 3     microsoft.com.     1 3097
    ## 4         apple.com.     1  942
    ## 5        google.com.     1 3340

``` {.r}
## parallel queries
library(foreach)
library(doParallel)
```

    ## Loading required package: iterators
    ## Loading required package: parallel

``` {.r}
library(data.table)

alexa <- fread("data/top-1m.csv") # http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

n <- 100 # top 'n' to resolve (change it to 10000 on your own as that # makes the README builds churn too long)

registerDoParallel(cores=6) # set to what you can on your system
output <- foreach(i=1:n, .packages=c("Rcpp", "resolv")) %dopar% resolv_a(alexa[i,]$V2)
names(output) <- alexa[1:n,]$V2
head(output)
```

    ## $google.com
    ##  [1] "74.125.226.64" "74.125.226.65" "74.125.226.66" "74.125.226.67" "74.125.226.68" "74.125.226.69" "74.125.226.70"
    ##  [8] "74.125.226.71" "74.125.226.72" "74.125.226.73" "74.125.226.78"
    ## 
    ## $facebook.com
    ## [1] "173.252.110.27"
    ## 
    ## $youtube.com
    ##  [1] "74.125.226.0"  "74.125.226.1"  "74.125.226.2"  "74.125.226.3"  "74.125.226.4"  "74.125.226.5"  "74.125.226.6" 
    ##  [8] "74.125.226.7"  "74.125.226.8"  "74.125.226.9"  "74.125.226.14"
    ## 
    ## $yahoo.com
    ## [1] "98.138.253.109" "98.139.183.24"  "206.190.36.45" 
    ## 
    ## $baidu.com
    ## [1] "123.125.114.144" "220.181.111.85"  "220.181.111.86" 
    ## 
    ## $wikipedia.org
    ## [1] "208.80.154.224"

### References

-   <http://www.nlnetlabs.nl/projects/ldns/>

### See Also

-   <http://www.nlnetlabs.nl/projects/ldns/>
-   <http://dds.ec/blog/posts/2014/Apr/making-better-dns-txt-record-lookups-with-rcpp/>
