# AIREP v0.2 — JSON input admissibility (normative)

> **Normative.** The key words MUST, MUST NOT, SHOULD, MAY are per BCP 14 (RFC 2119, RFC 8174).

**Purpose.** AIREP v0.2 normatively selects RFC 8785 (JCS) canonicalization (AD-04). RFC 8785
constrains the JSON data it will canonicalize, but AIREP has not previously stated **where that input
boundary is enforced**. This document makes the boundary mechanically enforceable and
cross-language deterministic. Adopted by **AD-17**.

It defines **raw-input admissibility and the construction of the JSON data model** used by AIREP
Core. It does **not** change assurance-class semantics
([`CONFORMANCE_CLASSES.md`](./CONFORMANCE_CLASSES.md) is unaffected), does not modify
[`INTEGRITY.md`](./INTEGRITY.md), and does not change the wire version, which remains `0.2`.

---

## 1. The Core principle

> Identical raw AIREP artifact bytes MUST produce either the same admissible JSON data model in every
> conforming implementation, or the same rejection outcome.

Host-parser behaviour is **not** a protocol choice. No first-wins/last-wins resolution, and no
arbitrary-precision-versus-binary64 variance, may determine `jcs-bytes`.

## 2. Processing order

```text
raw artifact bytes
    -> UTF-8 / JSON lexical admissibility            (§3, §7)
    -> duplicate-member and Unicode-domain validation (§4, §5)
    -> deterministic JSON data-model construction     (§5, §6)
    -> finite-number gate                             (§6.2)
    -> Core schema / semantic validation              (§6.4)
    -> RFC 8785 canonicalization
    -> jcs-bytes -> integrity / signature / class processing
```

**No lossy host-language object model may precede a check whose evidence that model would destroy.**
Duplicate-member detection in particular MUST occur while the raw parse still carries the
information; an ordinary map-collapsing parse erases it.

## 3. Provenance of each rule — inherited vs AIREP-selected

These do not share the same standards provenance, and the distinction is load-bearing.

### 3.1 Inherited through RFC 8785 / I-JSON

Consequences of the RFC 8785 selection AIREP already made:

- no duplicate object member names;
- duplicate identity determined **after** JSON escape processing;
- UTF-8 and the valid I-JSON string domain;
- no surrogate code points exposed as string data;
- no Unicode noncharacters;
- JSON number data represented through IEEE-754 binary64 semantics;
- a non-finite numeric state cannot be canonicalized;
- parsed string value preserved; no Unicode normalization.

### 3.2 AIREP deterministic Core policy — NOT inherited

- **An initial UTF-8 BOM is rejected** (§7).

RFC 8259 requires a sender not to emit a BOM but permits a parser to **ignore** one it encounters.
Rejection is therefore **AIREP's own receiver policy**, chosen to eliminate receiver variance. It
**MUST NOT** be described as an RFC 8785 requirement.

## 4. Duplicate member names

An object containing duplicate member names is **not admissible JCS input**. The artifact is rejected
before canonicalization.

- Detection is **recursive**, at every object depth.
- Member-name identity is compared **after JSON escape processing**, as Unicode character sequences.
  `"a"` and `"a"` are therefore the **same** member name.
- Detection MUST occur before any last-wins or first-wins collapse.
- This specification defines **neither** first-wins nor last-wins behaviour: the input is outside the
  admitted domain and does not proceed.

This applies to the **complete AIREP artifact**, not only to `profiles`.

## 5. Strings and Unicode

Raw JSON MUST decode under strict UTF-8 into string data admissible to the inherited JCS/I-JSON
domain. Reject at least: malformed UTF-8; an unpaired high surrogate; an unpaired low surrogate; any
surrogate code point otherwise exposed as string data; and Unicode noncharacters.

A **well-formed surrogate pair** representing a valid supplementary Unicode scalar remains
acceptable.

**Preservation.** After admission, the string's **Unicode value** is preserved exactly: no
normalization, no application subtype conversion before JCS, no rewriting of the semantic value.
**Source escape spelling is not semantic data** and need not be preserved — two valid spellings
decoding to the same Unicode value may canonicalize identically.

## 6. Numbers

### 6.1 The conversion is semantic, not a host technique

> Every admitted JSON number token is interpreted as the **correctly rounded IEEE-754 binary64 value**
> corresponding to that JSON numeric value, under the numeric data model RFC 8785 / ECMAScript JCS
> serialization uses.

The host parser's native numeric type is **not** normative. An implementation MUST NOT preserve
arbitrary-precision integer semantics inside the JCS path, and no implementation's current behaviour
is normative merely because it happens to match the target model. Both official implementations
independently implement this declared rule.

### 6.2 Finite-value gate

If the constructed value is **not finite**, the artifact is rejected **before** canonicalization. An
implementation MUST NOT emit `Infinity` or `NaN`, substitute `null`, or silently clamp. A token such
as `1E400` is therefore rejected.

### 6.3 Rounding is not failure

Finite loss of precision while constructing the binary64 data model is **not** an input failure.
`9007199254740993` may map to `9007199254740992` under binary64 semantics; that alone is **not** a
JCS rejection condition. RFC 8785 canonicalizes finite doubles far beyond the safe-integer range, and
its safe-integer guidance is a `SHOULD` for true integers — not a JCS-wide prohibition on the lexeme.

**Negative zero** is accepted where the numeric interpretation produces it; RFC 8785 determines its
canonical bytes (`0`). It is not rejected for host-language convenience.

Applications or profiles needing exact decimal or large-integer semantics **SHOULD** encode those
values as strings with their own declared semantics rather than relying on JSON Number.

### 6.4 Exact Core integers are bounded separately

Generic JSON-number semantics are **not** exact Core integer semantics. Where AIREP assigns exact
integer meaning to a field, that field's own constraint applies **after** deterministic binary64
construction, and rounding MUST NOT convert an out-of-range value into an accepted one.

**Schema audit (all five v0.2 Core schemas, at the time of adoption).** Exactly one Core integer
member carries an explicit safe-integer bound:

| Member | Bound |
|---|---|
| `common.schema.json` → `$defs.sequence` | `minimum: 0`, `maximum: 9007199254740991` |

No other integer-typed member in the five schemas declares a bound, and **no additional integer
constraint is invented here** for symmetry. The interaction is exact:

```text
sequence: 9007199254740993  ->  binary64 9007199254740992
                            ->  schema maximum 9007199254740991
                            ->  REJECTED
```

## 7. Encoding and BOM

Raw artifacts are **UTF-8**. A raw AIREP JSON artifact **beginning with a UTF-8 BOM is rejected**
before JSON semantic processing.

**Provenance, stated exactly.** The repository previously had **no normative BOM rule**. Both current
official runtime paths were **empirically observed** to reject a BOM. This document makes rejection
**explicit and portable** across conforming implementations.

> **Existing implementation agreement is not a previously specified protocol rule.** This rule is
> created here for the first time; the prior agreement is not evidence that the rule already existed,
> and it is not historical corpus evidence.

## 8. Relationship to other surfaces — ownership boundaries

This document owns **AIREP artifact raw JSON** admissibility only. Three surfaces stay distinct and
MUST NOT be collapsed:

| Surface | Owner |
|---|---|
| AIREP artifact raw JSON | **AD-17 / this document (Core)** |
| Profile-basis registry (operator measurement input) | the applicable class-verifier measurement contract |
| Validation-basis JSON Schema document | the applicable class-verifier measurement contract |

A measurement contract MUST rely on this Core precondition for artifact parsing and **MUST NOT**
define its own AIREP-artifact duplicate-member rule. Its separate registry and validation-basis
parsing rules remain necessary, because those are **measurement inputs, not AIREP artifacts**.

## 9. Evidence boundary

> The J1–J4 audit exposed a Core JCS input-admissibility **enforcement gap**. RFC 8785 already
> excludes duplicate property names and constrains string and number data through its JCS/I-JSON
> input requirements; AIREP did not make the raw-input enforcement point explicit, and the verifier
> path permitted ordinary parser collapse before that condition was checked. A concrete Python/Node
> divergence was demonstrated for an out-of-safe-range numeric token, because the Python path
> preserved arbitrary precision while the Node path constructed a binary64 value.

**No historical measured result has been shown to be wrong**, and historical evidence did **not**
measure the newly explicit raw-input boundary. Historical measurements remain frozen results under
their recorded basis and are not rescored. This document does not claim RFC 8785 permits duplicate
names, does not claim AIREP intentionally permitted them, and does not claim the two official
implementations have been shown to disagree on any historical artifact.
