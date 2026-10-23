# lightwell-coverage-demo

A constructed application, not a real project. Its `pom.xml` and `requirements.txt` pin library versions chosen so a
dependency scan shows every Lightwell coverage outcome: fully covered, partly covered, covered but not itemised,
covered with an unpublished newer build, and not covered. The covered versions were taken from what the Lightwell
Network API listed in October 2026, so the mix will drift as Lightwell's catalog and the public advisory databases change.

It exists to be scanned. Do not build or deploy it: the versions are deliberately old and vulnerable.

To scan it live, push this folder to a public GitHub repository and give the scanner that repository's name. In demo
mode it is served from recorded data as `demojam/lightwell-coverage-demo`.
