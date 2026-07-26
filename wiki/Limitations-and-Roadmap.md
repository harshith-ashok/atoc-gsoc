# Limitations and Roadmap

This is a research prototype. The output is "possible clone candidates for
review," never "confirmed affected packages." This page lists the concrete
gaps behind that disclaimer, and what closing each one would actually take
— framed as research questions, not just a bug list.

## Lexical similarity is not semantic equivalence

A regex match on `strcpy(a, b)` doesn't know whether `a` is
attacker-controlled or a compile-time constant. Closing this gap means
moving from text matching to structural matching:

- Parse matched code with an actual C/Python grammar (e.g. `tree-sitter`)
  instead of regex, so a signature can require "a call to this function
  with this many arguments" instead of "text that looks like this."
- Track simple taint/reachability (is the buffer size checked before the
  copy?) — even a shallow, intra-procedural check would cut a large
  fraction of false positives on patterns like `strcpy`.

## Add-only patches produce no usable signature

If a patch only adds a bounds check without removing the original call
(common for hardening patches), there's no "vulnerable shape" to mine —
`samples/curl.diff` is the running example of this in the repo. A fix
would need to infer the vulnerable shape from context (e.g., "a call to
this function with no length argument") rather than requiring an explicit
removed line.

## Fix-present is a proximity heuristic, not a real check

`LocalScanner` and `DebianCodeSearchScanner` both check "does fix-shaped
text appear within N lines" (see [Scanning Strategies](Scanning-Strategies.md)).
That's blind to: the fix being in a different function in the same file,
the fix already existing in a form the loosened regex doesn't recognize,
or a coincidental match with no causal relationship to the vulnerable
line. A real version would diff the *matched* file against its own patched
form, not scan a text window.

## No ranking model beyond three confidence labels

`confidence` is `low`/`medium`/`high`, computed from how many literal
character runs survive in the generated regex (see
[Signature Generation](Signature-Generation.md) for the documented quirk
where abstracted-identifier wildcards themselves inflate this count). A
real ranking model would need labeled data — actual confirmed clones vs.
confirmed false positives — to train or even hand-tune thresholds against,
which this prototype doesn't have yet. Building that labeled set (e.g. by
running against a handful of well-studied CVEs with known clone
histories) is the natural next step before any ranking work is worth
doing.

## CVE tracker mode is a local stub

`atoc/tracker.py::CveTracker` reads a hand-maintained JSON file — see
[CVE Tracker Mode](CVE-Tracker-Mode.md). A real integration would pull
from the Debian Security Tracker (or another canonical source), resolve a
CVE to the *specific* patch(es) that fixed it per affected branch, and
handle a CVE having different patches on different release branches. This
is the highest-leverage piece of unfinished work: everything downstream
(signature generation, scanning) already works from a `Patch`, so wiring
in a real tracker is additive, not a rewrite.

## Ideas not yet started

- **Result de-duplication across CVEs**: if two different CVEs happen to
  produce overlapping signatures (common vulnerable idiom), findings could
  be merged/cross-referenced instead of reported twice.
- **CI mode**: a machine-readable exit code (e.g. non-zero if any
  `high`-confidence, `fix_present=False` finding exists) so this could gate
  a pipeline rather than only being run interactively.
- **False-positive rate measurement**: running the pipeline against a
  corpus with *known* clone/non-clone labels and reporting precision, to
  turn "expect false positives" from a disclaimer into a measured number.
