# Alpine CVE Collector

A simple `Go` program that collects data from various sources to generate a list of *common vulnerabilities and exposures* (CVEs) for **Alpine Linux**. 

## Goal

Our goal is to create a reliable and trusthworthy CVE list that can be consumed by tools that provide static security scanning to **alpine containers**. 

Currently, our main use case is to provide a list consumable by [Clair](https://github.com/coreos/clair) from the CoreOS team which does not support alpine containers at the moment. Please refer to the discussions on the matter [here](https://github.com/coreos/clair/issues/12) and [here](https://github.com/eedevops). 

## Overview

The following are the major steps
- Fetches CVEs from the [National Vulnerability Database](https://nvd.nist.gov/).
- Fetches known Alpine packages from the [Alpine Packages Repository](https://pkgs.alpinelinux.org/packages).
- Maps CVEs with the packages alpine packages affected.
- Filters CVEs and generates / uploads a list.

## TODOs

Our list of *todos* is availble by browsing our [*enhancement issues*](https://github.com/eedevops/alpine_issue_collector/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) but here are the major features to add:

- Improve reliability and trust of CVE list by adding the next two collector steps:
    + [Alpine Ports (aports)](http://git.alpinelinux.org/cgit/aports/log/)
    + [Alpine issues repository](http://bugs.alpinelinux.org/projects/alpine/issues?set_filter=1&tracker_id=1)
- Adding persistence / caching to collected data. 
- Performance improvements. 

## About us

This work was done as part of the Image Lifecycle Management (ILM) project in the [Engineering Excellence - DevOps Team](https://github.com/eedevops) within [HPE Software](http://www8.hp.com/us/en/software/enterprise-software.html). We are a small team of engineers focusing on developing innovative tools and solutions for DevOps. 

## Contributors

- Ricardo Quintana @rqc
- Mircea Borza @borzamircea
- Giovanni Matos @gmatoshp

## License

[Apache License Version 2.0](LICENSE.md)

