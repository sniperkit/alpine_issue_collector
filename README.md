# Alpine Issues Collector

This is the repository of a long-running program which will do the following:

- fetch the Alpine issues (bugs) from https://bugs.alpinelinux.org/projects/alpine/issues
- format issues to digest and analyze them correctly
- analyze text to identify issues related to known-vulnerabilities and extracting important features:
  + Target alpine versions, for fixes and the ones that are vulnerable
  + Target packages and versions (a.k.a. Clair Features)
  + Severity 
  + Who fixed it
  + Cross-referencing or extracting necessary / missing information from https://nvd.nist.gov/download.cfm 
  + etc...
- discard issues not related to vulnerabilities 
- upload / push vulnerability list as a file (preferrably in JSON or CSV format) to a given git repository.
- This should be repeated at a specified / configurable frequency.
