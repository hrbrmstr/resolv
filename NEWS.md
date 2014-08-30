
### News

- Version update to `0.2.3` removed `plyr` dependency; cleaned up tests; converted alexa CSV to rda file (can now do `data(alexa)`)
- Version update to `0.2.2` includes making the parameters fully consistent, making the vectorized functions work better and having even saner return values when there were errors or no records found
- Version update to `0.2.1` includes 2 memory fixes and better return types if no records are found
- Version update to `0.2.0` includes ability to (optionally - set the `full` parameter to `TRUE`) return `class`, `ttl` & `owner` fields, includes `resolve_ns()` and `NS()` functions, plus changes return type for a few functions.
- Version update to `0.1.2` after running `valgrind` and fixing some missing `free`'s (`#ty` to [@arj](http://twitter.com/arj)!)
- Version update to `0.1.1` as I modified some of the roxygen documentation to better make this work out of the box. Any help getting it to work on Windows is greatly appreciated
