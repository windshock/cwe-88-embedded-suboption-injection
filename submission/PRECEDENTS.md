# Precedents and CWE Boundary — Embedded Sub-option Injection

Supporting material for the proposed modification to **CWE-88: Improper Neutralization of
Argument Delimiters in a Command ('Argument Injection')**.

The purpose of this document is not to claim a new attack concept. It demonstrates that:

1. delimiter injection into embedded parameter languages is an established security pattern;
2. recent CVEs already map **single-argument, second-stage option parsing** to CWE-88; and
3. the current CWE-88 text would be more useful if this recurring shape were stated
   explicitly.

## Verification status

The strongest entries below were re-checked against primary or high-authority sources while
preparing this repository:

- CWE and CAPEC pages from the CWE/CAPEC programs;
- GitHub's reviewed advisory database for CVE-2026-40113 and CVE-2026-6437;
- AWS's security bulletin for CVE-2026-6437;
- the Cloud Foundry advisory and CVE/NVD record for CVE-2026-41013;
- the Black Hat DC 2010 archive for Connection String Parameter Pollution; and
- POSIX/Open Group utility syntax guidance for comma-separated values inside one option
  argument.

Re-check these sources immediately before final submission because advisory metadata and CWE
content can change.

---

## 1. Summary map

| Precedent | Embedded grammar | Attacker delimiter | Result | CWE relevance |
|---|---|---:|---|---|
| **CVE-2026-40113 — PraisonAI / gcloud** | one `--set-env-vars` argument containing comma-separated `KEY=VALUE` pairs | `,` | additional environment-variable definitions; duplicate-key override variant | **CWE-88** — strongest direct precedent |
| **CVE-2026-6437 — Amazon EFS CSI Driver** | mount option value interpreted as comma-separated mount options | `,` | arbitrary additional mount options | **CWE-88** — direct sub-option injection precedent |
| **CVE-2026-41013 — Cloud Foundry SMB volumes** | CIFS/mount option list | `,` | smuggled mount options bypass allowlist | **CWE-88** — direct command-option precedent |
| **CSPP — Black Hat DC 2010** | semicolon-delimited DB connection string | `;` | new/duplicate connection parameters, including target-server override | conceptual historical precedent; not a CWE mapping claim |
| **CAPEC-137 — Parameter Injection** | any text-delimited parameter encoding | encoding-specific | add/modify parameters | general attack-pattern precedent; explicitly related to CWE-88 |
| **CAPEC-460 — HTTP Parameter Pollution** | HTTP query/form parameter list | `&` | duplicate parameters can override hard-coded values | duplicate/pollution analogue; related to CWE-88 and CWE-235 |
| **POSIX Utility Syntax Guideline 8** | multiple option values in one command argument | commonly `,` | receiving utility parses internal list | standards evidence that one `argv` element can contain a second option grammar |

The key distinction for this CWE proposal is between the **OS argument vector** and the
**receiving command's logical argument grammar**:

```text
process invocation layer

argv[0] = program
argv[1] = --structured-option
argv[2] = "key1=value1,key2=<UNTRUSTED>"
                         |
                         | delimiter injection
                         v
receiving program's second-stage grammar

key1=value1
key2=value
key3=attacker-controlled
```

No new `argv` element is required for the receiving command to process an additional option.

---

## 2. Strongest direct precedent — CVE-2026-40113

**CVE-2026-40113 / GHSA-fvxx-ggmx-3cjg** is the most important precedent for the proposed
CWE-88 clarification.

The reviewed GitHub advisory describes PraisonAI building a single comma-delimited string
for `gcloud run deploy --set-env-vars` by interpolating externally influenced values. The
call uses Python's argument-list form rather than a shell command string. The advisory
explicitly explains that Python passes the constructed value as **one complete argument**
and that `gcloud` subsequently applies comma-based parsing itself.

Abstracted:

```text
caller
  |
  | argv element
  v
--set-env-vars
"A=trusted,B=<INPUT>"
              |
              +-- attacker input: value,C=attacker

receiver: gcloud
  |
  +--> A=trusted
  +--> B=value
  +--> C=attacker        <-- unintended logical option
```

The advisory also documents a duplicate-key variant in which attacker input creates a second
occurrence of a sensitive environment variable and a last-defined value can take precedence.

### Why it matters for this submission

This precedent establishes all of the important points at once:

- the process launcher uses a structured argument list;
- shell interpretation is not the injection boundary;
- the vulnerable text remains a single OS-level argument;
- the receiving utility parses a delimiter-based language inside that argument; and
- the reviewed advisory maps the vulnerability to **CWE-88**.

That makes the proposed change a clarification of existing real-world CWE-88 practice, not an
attempt to stretch CWE-88 into a new domain.

### Sources

- GitHub advisory:
  https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-fvxx-ggmx-3cjg
- GitHub reviewed advisory database:
  https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2026/04/GHSA-fvxx-ggmx-3cjg/GHSA-fvxx-ggmx-3cjg.json
- NVD:
  https://nvd.nist.gov/vuln/detail/CVE-2026-40113

---

## 3. Direct mount sub-option precedent — CVE-2026-6437

**CVE-2026-6437 / GHSA-mph4-q2vm-w2pw** affects the Amazon EFS CSI Driver.

The published advisory states that unsanitized values in `volumeHandle` and
`mounttargetip` can contain appended comma-separated values. The mount utility interprets
those values as additional mount options, so attacker-controlled logical options reach the
filesystem mount operation.

Abstracted:

```text
trusted mount construction
        |
        v
field=<UNTRUSTED>
        |
        +-- value,option1=x,option2=y
                    |
                    v
          receiving mount parser
                    |
                    +--> intended field/value
                    +--> injected option1
                    +--> injected option2
```

The GitHub reviewed advisory database maps the issue to **CWE-88**. AWS's security bulletin
also describes the comma-separated mount option injection behavior.

### Why it matters for this submission

This is a second independent product and parser family showing that CWE-88 is used for
**delimiter injection at a receiving command's internal option grammar**, not only for
whitespace/quote injection that creates top-level command-line switches.

### Sources

- GitHub advisory:
  https://github.com/kubernetes-sigs/aws-efs-csi-driver/security/advisories/GHSA-mph4-q2vm-w2pw
- GitHub reviewed advisory database:
  https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2026/04/GHSA-mph4-q2vm-w2pw/GHSA-mph4-q2vm-w2pw.json
- AWS Security Bulletin 2026-016:
  https://aws.amazon.com/security/security-bulletins/2026-016-aws/
- NVD:
  https://nvd.nist.gov/vuln/detail/CVE-2026-6437

---

## 4. Allowlist-bypass precedent — CVE-2026-41013

**CVE-2026-41013** affects Cloud Foundry's SMB volume mount handling.

Cloud Foundry describes a tenant-controlled comma that can smuggle arbitrary CIFS mount
options and bypass the intended mount-option allowlist. The CVE record assigns
**CWE-88**.

The impact is especially useful for explaining why embedded sub-option injection is not a
mere parsing oddity: the injected logical options cross a security boundary that was meant
to restrict which kernel mount behaviors tenants could request.

### Why it matters for this submission

CVE-2026-41013 independently reinforces the same mapping pattern:

```text
allowed outer value
      + attacker-controlled comma-delimited text
                         |
                         v
             forbidden logical option
                         |
                         v
               receiver applies option
```

Again, the security-relevant token is a delimiter in an internal command option grammar.

### Sources

- Cloud Foundry advisory:
  https://www.cloudfoundry.org/blog/cve-2026-41013-tenant-controlled-comma-smuggles-arbitrary-cifs-mount-options-2/
- NVD:
  https://nvd.nist.gov/vuln/detail/CVE-2026-41013

---

## 5. Historical conceptual precedent — Connection String Parameter Pollution

At **Black Hat DC 2010**, **Chema Alonso and Jose Palazon** presented *Connection String
Parameter Pollution Attacks* (CSPP). Black Hat's archived session page lists both speakers
and describes attacks against dynamically constructed database connection strings.

CSPP is not a command-line CWE-88 example, so this repository does **not** use it as evidence
of a historical CWE-88 mapping. It is useful because it demonstrates the same underlying
parser pattern in another structured string grammar:

```text
trusted parameter list
        |
        +-- untrusted field inserted as text
                         |
                         +-- separator injected
                                      |
                                      v
                         new or duplicate parameter
                                      |
                                      v
                         connection behavior changes
```

Published descriptions of CSPP specifically discuss semicolon-separated connection
parameters and the ability to duplicate/overwrite values so that the target server,
authentication behavior, or other connection properties change.

### Why it matters for this submission

CSPP shows that the *attack idea* is not new. That actually strengthens a **modification**
submission: there is no need to invent a new weakness category. Instead, CWE-88 should make
its command-specific manifestation of this established parser-boundary pattern explicit.

### Sources

- Black Hat DC 2010 archive:
  https://blackhat.com/html/bh-dc-10/bh-dc-10-archives.html
- Black Hat DC 2010 schedule:
  https://blackhat.com/html/bh-dc-10/bh-dc-10-schedule.html
- White paper:
  https://www.blackhat.com/presentations/bh-dc-10/Alonso_Chema/Blackhat-DC-2010-Alonso-Connection-String-Parameter-Pollution-wp.pdf
- Contemporary Dark Reading coverage:
  https://www.darkreading.com/vulnerabilities-threats/black-hat-dc-researchers-reveal-connection-string-pollution-attack

---

## 6. CAPEC already generalizes delimiter-based parameter injection

### CAPEC-137 — Parameter Injection

CAPEC-137 describes a meta attack pattern in which a parameter encoding uses text
characters as separators and attacker-controlled text injects those separators to add or
modify parameters. Importantly, CAPEC states that this concept applies to **any encoding
scheme** in which text characters identify/separate parameters; HTTP is presented only as
an example.

CAPEC-137 directly lists **CWE-88** as a related weakness.

That gives a useful abstraction ladder:

```text
CAPEC-137                       CWE-88 clarification
parameter encoding             command argument grammar
      |                              |
text delimiter                 embedded sub-option delimiter
      |                              |
new parameter                  new logical command option
```

Source:
https://capec.mitre.org/data/definitions/137.html

### CAPEC-460 — HTTP Parameter Pollution

CAPEC-460 specializes the same idea for HTTP. It documents duplicate parameter injection,
including the possibility that a backend ignores an earlier hard-coded value and uses an
attacker-controlled later occurrence.

CAPEC-460 lists **CWE-88** and **CWE-235** among its related weaknesses.

This is helpful for the boundary analysis:

- delimiter injection that **creates the additional logical parameter/option** aligns with
  the injection weakness;
- incorrect processing of multiple same-named parameters can additionally align with
  CWE-235.

Source:
https://capec.mitre.org/data/definitions/460.html

---

## 7. POSIX confirms that a single command argument can contain a second grammar

The embedded-sub-option model is not merely an implementation quirk.

POSIX/Open Group Utility Syntax Guideline 8 describes situations where multiple values that
follow a single option are represented as **one argument**, using comma or blank separators,
and the receiving utility parses the comma-separated list itself.

Conceptually:

```text
argc/argv layer

argv[N] = "one,two,three"
             |
             v
utility parser layer

value[0] = one
value[1] = two
value[2] = three
```

That standardized convention is exactly why secure process invocation and secure *argument
content construction* are different problems. An argument-array API can faithfully preserve
`argv[N]` while the target utility legitimately assigns delimiter semantics to characters
inside it.

Sources:

- POSIX Utility Syntax Guidelines:
  https://pubs.opengroup.org/onlinepubs/9699919799.orig/basedefs/V1_chap12.html
- Open Group rationale discussing comma-separated lists in one argument:
  https://pubs.opengroup.org/onlinepubs/9799919799/xrat/V4_xbd_chap01.html

---

## 8. Why this is CWE-88 and not only CWE-141

CWE-141 is **Improper Neutralization of Parameter/Argument Delimiters**. Its description is
broad: an upstream component receives input and fails to neutralize elements that become
parameter/argument delimiters in a downstream component.

That clearly overlaps the general parser-boundary mechanism.

However, the proposed pattern occurs specifically in **program invocation and command option
processing**, which is CWE-88's functional area. More importantly, multiple current CVEs
using this exact command/sub-option shape are already mapped to CWE-88.

The proposed modification therefore does not argue:

> CWE-141 is wrong; use CWE-88 instead everywhere.

It argues:

> CWE-88 should explicitly document its command-specific instance of this delimiter pattern,
> because current CWE-88 CVE mappings already do so and current examples do not make the
> single-`argv`/second-stage-parser case obvious.

Sources:

- CWE-88: https://cwe.mitre.org/data/definitions/88.html
- CWE-141: https://cwe.mitre.org/data/definitions/141.html

---

## 9. Why duplicate-option behavior is not enough to move the proposal to CWE-235

CWE-235 covers incorrect handling when parameters/fields/arguments with the same name occur
more times than expected.

A duplicate security-sensitive option can be an important exploitation step:

```text
endpoint=trusted,id=<INPUT>
                    |
                    +-- 42,endpoint=attacker
                              |
                              v
                      duplicate endpoint
                              |
                     receiver precedence
```

But duplicate handling is **not necessary** for the proposed CWE-88 pattern:

```text
mode=normal,id=<INPUT>
                |
                +-- 42,new_option=attacker
                              |
                              v
                   previously absent option
```

The second example is still successful argument injection, even though there is no duplicate
name for CWE-235 to handle.

Therefore:

- **CWE-88** explains how attacker text becomes an unintended logical command option;
- **CWE-235** may explain how an injected duplicate is resolved after it exists.

Source:
https://cwe.mitre.org/data/definitions/235.html

---

## 10. Why this is not necessarily CWE-78

Classic OS command injection requires a command interpreter or equivalent parsing context in
which attacker-controlled syntax can create or alter commands.

The proposed CWE-88 case does **not** require a shell:

```text
structured process API
      |
      v
receiving executable
      |
      v
its own option parser
```

CVE-2026-40113 is decisive because the advisory explicitly discusses the absence of
`shell=True` and explains that the injection occurs when `gcloud` parses its own argument.

A separate CWE-78 weakness can coexist if the injected option later reaches a command
interpreter, but that is not required for embedded sub-option injection itself.

---

## 11. Proposed reviewer-facing conclusion

The evidence supports a **CWE-88 modification**, not a new CWE:

> Recent vulnerabilities already assigned CWE-88 demonstrate argument injection in which a
> caller safely preserves OS-level argument boundaries but embeds untrusted data inside an
> argument that the receiving command reparses as a delimiter-separated sub-option list.
> The attacker injects a delimiter in that second-stage grammar to create an unintended
> logical option. Historical parameter-pollution research and CAPEC-137 show that the parser
> mechanism is established, while CWE-235 separately covers cases where an injected
> duplicate is then handled incorrectly. Explicitly documenting this shape in CWE-88 would
> align the entry's text and mitigations with existing CWE-88 vulnerability mappings and
> prevent the common misconception that argument-array APIs alone eliminate all argument
> injection.

---

## 12. Citation checklist before submission

Before the final CWE web-form submission:

- [ ] Re-check the current CWE-88 version and modification history.
- [ ] Re-check CVE-2026-40113 CWE mapping and advisory wording.
- [ ] Re-check CVE-2026-6437 CWE mapping and AWS bulletin.
- [ ] Re-check CVE-2026-41013 CNA/NVD CWE mapping.
- [ ] Re-check CAPEC-137 and CAPEC-460 current versions.
- [ ] Re-check CWE-141 and CWE-235 current descriptions.
- [ ] Verify Black Hat archive/white-paper URLs remain reachable.
- [ ] Verify the POSIX/Open Group reference URL used in the final submission.
