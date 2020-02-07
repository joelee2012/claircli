[![Build Status](https://travis-ci.com/joelee2012/claircli.svg?branch=master)](https://travis-ci.com/joelee2012/claircli)
[![Coverage Status](https://coveralls.io/repos/github/joelee2012/claircli/badge.svg?branch=master)](https://coveralls.io/github/joelee2012/claircli?branch=master)
# claircli
## claircli is a command line tool to interact with [CoreOS Clair](https://github.com/quay/clair)
- analyze loacl/remote docker image with [Clair](https://github.com/quay/clair)
- generate HTML/JSON report, the html report template is from [analysis-template.html](https://github.com/jgsqware/clairctl/blob/master/clair/templates/analysis-template.html)

# Installation

```bash
pip install claircli
```

# Commands

```
claircli -h
usage: claircli [-h] [-V] [-c CLAIR] [-w WHITE_LIST] [-T THRESHOLD]
                [-f {html,json}] [-L LOG_FILE] [-d] [-l LOCAL_IP | -r]
                images [images ...]

Command line tool to interact with CoreOS Clair, analyze docker image with
clair in different ways

positional arguments:
  images                docker images or regular expression

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -c CLAIR, --clair CLAIR
                        clair url, default: http://localhost:6060
  -w WHITE_LIST, --white-list WHITE_LIST
                        path to the whitelist file
  -T THRESHOLD, --threshold THRESHOLD
                        cvd severity threshold, if any servity of
                        vulnerability above of threshold, will return non-
                        zero, default: Unknown, choices are: ['Defcon1',
                        'Critical', 'High', 'Medium', 'Low', 'Negligible',
                        'Unknown']
  -f {html,json}, --formats {html,json}
                        output report file with give format, default: ['html']
  -L LOG_FILE, --log-file LOG_FILE
                        save log to file
  -d, --debug           print more logs
  -l LOCAL_IP, --local-ip LOCAL_IP
                        ip address of local host
  -r, --regex           if set, repository and tag of images will be treated
                        as regular expression
  -H, --http            use http instead of https to access the docker registry (HTTPS is default)

Examples:

    # analyze and output report to html
    # clair is running at http://localhost:6060
    claircli example.reg.com/myimage1:latest example.reg.com/myimage2:latest

    # analyze and output report to html
    # clair is running at https://example.clair.com:6060
    claircli -c https://example.clair.com:6060 example.reg.com/myimage1:latest

    # analyze and output report to html, json
    claircli -f html -f json example.reg.com/myimage1:latest

    # analyze with threshold and white list
    claircli -t High -w white_list_file.yml example.reg.com/myimage1:latest

    # analyze image on local host
    claircli -l <local ip address> myimage1:latest myimage2:latest

    # analyze image on other host foo
    export DOCKER_HOST=tcp://<ip of foo>:<port of docker listen>
    claircli -l <local ip address> myimage1:latest

    # analyze with regular expression, following will match
    # example.reg.com/myimage1:latest
    # and example.reg.com/myimage2:latest
    claircli -r example.reg.com/myimage:latest

    # analyze with regular expression, following will match
    # example.reg.com/myimage1:latest only
    claircli -r example.reg.com/^myimage1$:^latest$

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