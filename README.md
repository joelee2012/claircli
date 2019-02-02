[![Build Status](https://travis-ci.com/joelee2012/claircli.svg?branch=master)](https://travis-ci.com/joelee2012/claircli)
[![Coverage Status](https://coveralls.io/repos/github/joelee2012/claircli/badge.svg?branch=master)](https://coveralls.io/github/joelee2012/claircli?branch=master)
# claircli
## claircli is a simple command line tool to interact with [CoreOS Clair](https://github.com/coreos/clair)
- analyze loacl/remote docker image with [clair](https://github.com/coreos/clair)
- generate HTML/JSON report, the html report template is from [analysis-template.html](https://github.com/jgsqware/clairctl/blob/master/clair/templates/analysis-template.html)

# Installation

```bash
pip install claircli
``` 

# Commands

```
claircli -h
usage: claircli [-h] [-V] {batch-analyze,fuzzy-analyze} ...

Simple command line tool to interact with CoreOS Clair

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

subcommands:
  Subcommands of claircli

  {batch-analyze,fuzzy-analyze}
    batch-analyze       Batch analyze docker images with clair
    fuzzy-analyze       Fuzzy analyze docker images with clair
```

## Optional whitelist yaml file

This is an example yaml file. You can have an empty file or a mix with only `common` or `<distribution>`.

```yaml
common:
  CVE-2017-6055: XML
  CVE-2017-5586: OpenText
ubuntu:
  CVE-2017-5230: XSX
  CVE-2017-5586: OpenText
alpine:
  CVE-2017-3261: SE
```