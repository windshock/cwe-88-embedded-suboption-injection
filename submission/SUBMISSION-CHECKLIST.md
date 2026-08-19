# CWE-88 Modification — Submission Checklist

This checklist is modeled on the workflow observed for the prior CWE-69 modification
submission: the external form submission is assigned an `ES...` communication ID and then
surfaced as an issue in the CWE Content Development Repository for tracking.

The current official CWE contribution guidance says that a **modification to an existing
weakness** has three required elements:

1. submitter contact information;
2. the relevant CWE-ID; and
3. details of the suggested modification.

This repository intentionally provides substantially more supporting material than the
minimum so that the requested modification, evidence, precedents, and overlap boundaries are
independently reviewable.

## Before submitting

- [ ] Re-read current CWE-88, CWE-141, and CWE-235 pages and confirm no newer CWE release has
      already incorporated the proposed clarification.
- [ ] Re-check the CWE mappings and descriptions for CVE-2026-40113, CVE-2026-6437, and
      CVE-2026-41013 against the CNA/vendor advisory and NVD/CVE record.
- [ ] Run the generalized demonstrator:

```sh
bash submission/scripts/run_demo.sh
```

- [ ] Confirm the final line is:

```text
[PASS] all generalized CWE-88 embedded sub-option tests passed
```

- [ ] Refresh captured evidence after any intentional PoC/script modification:

```sh
bash submission/scripts/capture_evidence.sh
```

- [ ] Run the generalized-submission hygiene validator:

```sh
bash tools/validate-submission.sh
```

It should confirm the required files, source integrity manifest, product-independent boundary,
and absence of prohibited compiled artifacts.

- [ ] Build the submission package:

```sh
bash tools/make-submission.sh
```

- [ ] Verify both files exist:

```text
dist/cwe-88-embedded-suboption-injection-submission.zip
dist/cwe-88-embedded-suboption-injection-submission.zip.sha256
```

- [ ] Open `submission/FORM-TEXT.md` as the canonical concise wording, or use
      `submission/form-description.txt` for direct plain-text copy/paste.
- [ ] Keep the action as **Modification**, not New CWE.
- [ ] Identify **CWE-88** as the relevant/affected CWE.
- [ ] Provide the suggested modification details from the form text and include the public
      GitHub repository as the full rationale / generalized evidence reference.

## Recommended submission framing

Use the conservative framing:

> Recent vulnerabilities already assigned CWE-88 demonstrate command option injection in
> which OS-level argument boundaries remain intact but a receiving command reparses one
> argument as a delimiter-separated option language. The requested modification aligns
> CWE-88's wording, mitigation guidance, and examples with that observed mapping practice
> while explicitly bounding overlap with CWE-141 and CWE-235.

Avoid framing the request as a newly discovered attack category. The argument is stronger as
a **CWE content clarification backed by current mapping practice**.

## Most important reviewer risk

The current CWE-88 Description is explicitly framed around constructing a command **string**.
The generalized demonstrator uses a structured argument array.

Therefore be prepared for either outcome:

1. **Preferred:** CWE-88 Description/Extended Description is generalized to cover logical
   option delimiters interpreted by a receiving command within one OS-level argument.
2. **Fallback:** CWE-88 keeps its current Description but gains Mapping Notes / Extended
   Description text defining when embedded option parsing is CWE-88 versus CWE-141.

The fallback is still a useful CWE content improvement and should not be treated as failure.
See `REVIEWER-NOTES.md` for the full objection analysis.

## Product-specific disclosure boundary

The submission package is intentionally product-independent. Do not add non-public vendor
binaries, non-public product payloads, credentials, or confidential disclosure details to
this repository.

Public CVEs and published advisories may be used as precedent. A separately coordinated
product vulnerability can be proposed later as a Selected Observed Example once its public
disclosure status permits it.

## After submitting

When the CWE Program sends the receipt:

- [ ] Record the `ES...` submission communication ID.
- [ ] Record the Content Development Repository issue number/URL when created.
- [ ] Update the repository status from `prepared` to `submitted / Ack-Receipt`.
- [ ] Add the submission ID and public CDR issue link to the root README.
- [ ] Do **not** describe the submission as accepted merely because a receipt was issued.
- [ ] Track phase/status changes in the CDR issue.

The prior CWE-69 submission illustrates the distinction: receipt created a public CDR issue
and `Phase02-Ack-Receipt`; that means the submission was acknowledged, not that the proposed
content change had been accepted or published.

## If the CWE Team requests additional detail

Prioritize the following materials:

1. `submission/FORM-TEXT.md` — concise requested change;
2. `submission/modification-details.md` — full field-level rationale;
3. `submission/REVIEWER-NOTES.md` — CWE-141 / CWE-235 / current-description boundary;
4. `submission/PRECEDENTS.md` — independent real-world mappings;
5. `submission/evidence/run_demo.txt` — decisive `argc=3` comparison; and
6. `submission/poc/` — minimal product-independent source.

If reviewers challenge CWE-88 versus CWE-141, lead with the **current CWE-88 Program
Invocation scope and the direct CNA mappings of CVE-2026-40113 / CVE-2026-6437 /
CVE-2026-41013**, then acknowledge that CWE-141 is the broader generic delimiter weakness.

## Official process reference

- CWE Content Submission overview:
  https://cwe.mitre.org/community/submissions/overview.html
