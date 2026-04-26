# Attack Of The Clones

> Fight Back Using Code Duplication Detection from Security Patches

---

## Description
The clone attack where identical copies of vulnerable code are embedded across multiple executables is a distribution wide security problem. The current approach necessitates extensive tracking of code duplication and individual patching or recompiling of each affected binary, significantly increasing the complexity and overhead of security updates. As a result, ensuring timely remediation across all instances of the code becomes challenging, leaving systems more susceptible to prolonged exposure to vulnerabilities.

The goal of this project is to automate the detection of code duplication in the archive by using security patches, converting these patches into loose regex patterns, and then scanning the archive for security‑related code duplication.

---

## Application tasks

- Extract patch metadata from debian security tracker. May need to standardization of patch annotation and writing a custom parser
- Research way to transform patch to loosely code signature using limited regex (re2) that could be used by codesearch.debian.net
- Use codesearch.debian.net to find code duplication in the archive
- write report about attack of clone found 


