#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AIREP v0.2 Python reference interop evaluator (AD15-IR-2), post-erratum.

Implements ``INTEROP_REFERENCE_EVALUATOR_CONTRACT.md`` at contract basis
``51c14fe11ae7a94e9c55e30490a754bbe4ccf505``
(sha256 ``6e420dadbd869afad0f883cbfb26e4fb8197a0cc70b5fb869f57a5ceefad2059``,
git blob ``db4ec989b11db5606127cef369cc4dc7ca799ab9``),
alongside ``INTEROP_CORPUS_CONTRACT.md``
(sha256 ``ac15ec39dd738d5c4ab6cba03aad92682a0f1b3af1d613ff88b26f2f4587d8bd``,
UNCHANGED by Erratum 7), i.e. the canonical post-Erratum-7 contracts, over the
FROZEN Python class verifier, which is invoked as a SUBPROCESS and is never
imported, vendored or re-implemented (contract 3).

Erratum 7 rulings carried here -- the largest round in this chain, raised by a
PRE-PIN adversarial review rather than by a remediation round, and reworked
across several passes in which some rulings were REVERSED. Where this file and
any summary of it disagree, the contract governs:

  * E7-1  ruling ``AD15-IR-12``: CANONICAL INVOCATION ORDER AND FATAL-RUN
          FAIL-FAST. Invocations proceed in ascending UTF-8 byte order of
          ``artifact_path``; ``verifier-not-invocable`` contributes NO entry and
          aborts; ``verifier-run-invalid`` DOES contribute its entry and aborts;
          a clean ``exit 0`` never aborts, even carrying a non-empty
          ``authenticated_withheld`` channel. TWO BEHAVIOURAL CORRECTIONS HERE:
          this lane invoked EVERY artifact and only then swept the exit codes,
          so a four-artifact bundle whose first artifact exited 2 yielded four
          entries where the ruling now yields one; and a malformed ``exit 0``
          raised out of the decoder BEFORE its entry was appended, yielding no
          entry for a process that had plainly produced a concrete result. See
          ``stage_invoke``;
  * E7-2  ruling ``AD15-IR-13``: TOTAL FAILURE PRECEDENCE. Pairwise ordering
          does not scale -- every unordered pair is a latent divergence -- so
          contract 8.6 replaces it with a thirteen-stage pipeline in which a
          stage RUNS TO COMPLETION over the whole bundle before the next begins.
          BEHAVIOURAL CORRECTION: this lane validated each listed path
          end-to-end in manifest order, so stages 5, 6 and 7 were interleaved
          and a bundle with one missing file, a different unreadable file and a
          third mismatched digest reported whichever came first. The barriers
          are now explicit and each stage collects its whole candidate set
          before selecting by ``(stage_rank, reason_rank_within_stage,
          canonical_artifact_path [, json_pointer])``. See ``_evaluate``,
          ``_stage_select`` and ``REASON_RANK_WITHIN_STAGE``;
  * E7-7  ruling ``AD15-IR-14``: a POST-IDENTITY OPERATOR ASSERTION MISMATCH IS
          RESULT-BEARING -- ``operator-input-assertion-mismatch``, ERROR, exit
          3. BEHAVIOURAL CORRECTION: this lane raised a CLI usage error at exit
          2. CLOSES this lane's own declared ambiguity A1;
  * E7-8/E7-23 ruling ``AD15-IR-15``: THREE PROCESS OUTCOMES, DISTINGUISHED. A
          process that never started contributes no entry; one that started and
          did not exit normally contributes a FULL entry with
          ``verifier_exit_code: null`` and ``verifier_result: null``; one that
          exited normally carries the integer verbatim. No signal name, signal
          number or synthesized exit code enters ANY normative field -- only
          ``detail``, which contract 8.7 places in Class 4. Abnormal termination
          is the absence of an EXIT CODE, not of a process ATTEMPT, so it is
          emphatically not the ``AD15-IR-11`` shape;
  * E7-28 ruling ``AD15-IR-16``: ``withheld_reasons`` HAS A PINNED ENTRY SHAPE
          -- one entry per (artifact, channel, reason), ordered by that triple
          in UTF-8 byte order. BEHAVIOURAL CORRECTION: this lane emitted a
          per-ARTIFACT object with the two channel arrays inline. CLOSES this
          lane's own declared ambiguity A5;
  * E7-29 ruling ``AD15-IR-17``: DUPLICATE MANIFEST MEMBERS are detected WHILE
          PARSING and are never resolved by a runtime default. A duplicate
          TOP-LEVEL ``scenario_id`` is the exit-1 band; a NESTED ``scenario_id``
          and every other duplicate are ``manifest-invalid`` at stage 4.
          BEHAVIOURAL CORRECTION: this lane relied on last-wins and recorded
          that reliance. CLOSES this lane's own declared ambiguity A8;
  * E7-SR-2/8/9 ruling ``AD15-IR-18``: ONE CLOSED ``artifact_ref`` PROJECTION,
          total over every JSON value, with its source pinned per outcome --
          Source A the accepted ``exit 0`` verdict (verbatim, behind a gate that
          rejects an unclosed nested object), Source B EVERY OTHER EMITTED ENTRY
          (defined by EXCLUSION), Source C no entry at all. BEHAVIOURAL
          CORRECTION: this lane treated an EMPTY ``record_id`` as no identity,
          which is a ``minLength`` rule absent from the frozen schema, and it
          rejected a non-string ``chain_id`` as ``bundle-shape-invalid``, which
          8.2.2 does not define. Both removed;
  * E7-SR-3 ruling ``AD15-IR-19``: the manifest ``path`` grammar is LEXICAL and
          CLOSED, and an evaluator NEVER normalizes a path into acceptance;
  * E7-SR-3 ruling ``AD15-IR-20``: the JSON BYTE DOMAIN is closed -- UTF-8 only,
          no BOM, no UTF-16/UTF-32, strict lossless decoding, no U+FFFD, no
          repair -- with the failure assigned by which file it is; plus RFC
          8785's other two input requirements at stage 8 (unpaired surrogate,
          duplicate member name) and the numeric one deliberately LEFT at stage
          10 so its ``json_pointer`` survives;
  * E7-SR-1 contract 8.7: the FOUR-CLASS normative surface, the closed result
          member set, and the cross-lane projection harness duty 6 compares as
          RFC 8785 canonical bytes. The earlier binary model was CONTRADICTORY
          -- it called every ``artifacts[]`` field and all of
          ``verifier_digests`` normative, while ``verifier_stderr_digest`` and
          each lane's own class-verifier digest are EXPECTED to differ. See
          ``normative_projection`` and ``validate_result_shape``;
  * E7-19 ``json_pointer`` is RFC 6901 against the FILE the violation is in,
          never the request envelope. CLOSES this lane's recorded ambiguity A2
          in the direction it had already inferred.

Erratum 6 rulings carried here:

  * E6-1  ruling ``AD15-IR-9``: ENTRY KIND REQUIRES AUTHORITATIVE NO-FOLLOW
          METADATA. Contract 8.2.2's first boundary row said the inspection was
          ``lstat`` OR EQUIVALENT, and the two lanes read "or equivalent"
          differently. An enumeration-time type hint -- ``d_type`` from
          ``readdir``, ``os.DirEntry.is_file()`` and their equivalents -- is NOT
          kind evidence on its own, because it may answer from a value the
          directory read happened to carry without any metadata lookup on the
          entry, and only on filesystems that populate it. For EVERY enumerated
          entry the evaluator MUST now perform a SEPARATE no-follow metadata
          lookup, and where that lookup cannot complete the reason is
          ``bundle-entry-uninspectable``. THIS IS THE ONE BEHAVIOURAL CHANGE IN
          THIS LANE (contract 13 step 2): ``entry_kind`` previously answered
          from ``os.DirEntry``, and was MEASURED returning
          ``(is_symlink=False, is_dir=False, is_file=True)`` WITHOUT RAISING on
          a directory at mode ``0o444``, where the peer lane's per-entry lookup
          failed ``EACCES``. It now calls ``os.lstat`` per entry and derives the
          kind from ``st_mode``. The defect is CROSS-PLATFORM DETERMINISM, not
          semantics -- no mandatory scenario's Level-1 value moves;
  * E6-2  ruling ``AD15-IR-10``: RUN VALIDITY PRECEDES TIER WITHHELD. Contract
          7.1 is evaluated ONLY AFTER every artifact invocation in the scenario
          has passed the 7.2 process- and result-shape guard. Where an
          ERROR-class process or run invalidity and a non-empty
          ``authenticated_withheld`` channel are both present on the same
          bundle, the ERROR outcome is reported -- a verifier that misbehaved AS
          A PROCESS cannot be trusted to have produced a meaningful withheld
          channel either, so ``MEASUREMENT_INVALID`` would attribute the failure
          to the tier when it belongs to the run. This lane already applied the
          7.2 guard first, so the ruling CONFIRMS its construction; NO
          BEHAVIOUR CHANGES. Contract 13 step 4 requires the ordering be TESTED
          rather than left to hold by accident, and it now is;
  * E6-3  ruling ``AD15-IR-11``: A SPAWN FAILURE PRODUCES NO ``artifacts[]``
          ENTRY. "Attempted" in contract 8.3.1 rule 3 means a process attempt
          that produced a CONCRETE PROCESS RESULT. Where the frozen verifier
          cannot be spawned at all (``verifier-not-invocable``) the current
          artifact contributes NO entry, while entries for invocations that
          completed EARLIER in the same bundle are RETAINED. No implementer
          fabricates an exit code, a verdict or a stderr digest for a process
          that never ran. This lane already did exactly this, so the ruling
          CONFIRMS it; NO BEHAVIOUR CHANGES, and contract 13 step 4's explicit
          test is now present.

Erratum 5 rulings carried here:

  * E5-1  ruling ``AD15-IR-8``: IDENTITY ESTABLISHMENT IS MONOTONIC. Once the
          root ``manifest.json`` bytes have been read, parsed as strict JSON and
          have yielded a registered ``scenario_id``, bundle identity IS
          established and no later filesystem, traversal or preflight failure
          can retroactively unestablish it. The worked case the ruling pins is a
          bundle directory at mode ``0o111``: traverse permission lets
          ``open(DIR/manifest.json)`` succeed while ``readdir(DIR)`` fails
          ``EACCES``, so the result is ``bundle-directory-unreadable`` at exit 3
          and NOT exit 1. This lane's structure already put the direct read
          strictly before any traversal, so the ruling CONFIRMS it; the worked
          case is now asserted rather than merely implied;
  * E5-2  the stale "three conditions" restatement of the exit-1 band is
          replaced by a reference to contract 5. Documentation only; the band
          itself is unchanged and this file already referenced the five
          conditions rather than a count;
  * E5-3  ``bundle-entry-uninspectable`` joins the closed registry -> ERROR,
          exit 3, ``artifacts: []``. It is the last gap in the filesystem
          taxonomy: an entry whose NAME was obtained by a successful enumeration
          but whose KIND could not be determined by a no-follow inspection.
          Its "``lstat`` OR EQUIVALENT" phrasing is SUPERSEDED by ``AD15-IR-9``
          (E6-1 above), which pins the lookup as a SEPARATE per-entry no-follow
          metadata call and excludes enumeration-time type hints.
          Calling that ``manifest-invalid`` would
          assert the layout is wrong when that is precisely what could not be
          established, and ``bundle-directory-unreadable`` does not fit either,
          because enumeration SUCCEEDED. This CLOSES recorded ambiguity A14
          AGAINST this lane's inferred mapping;
  * E5-4  ``frozen-identity-unreadable`` joins the closed registry, and the
          frozen-identity preflight ORDER is pinned: bundle identity first, then
          IMMEDIATELY the evaluator's own frozen identity pair, then everything
          else. If either frozen file cannot be READ the result is exit 3 with
          that reason, ``verifier_digests: null`` and ``artifacts: []``; if both
          are read the exact TWO-entry object is built from the RECOMPUTED
          values, and a mismatch keeps that actual two-entry object rather than
          the expected one. ``verifier_digests`` is therefore exactly two
          entries or ``null``, never a one-entry object. This CLOSES recorded
          ambiguity A15 AGAINST this lane's pre-erratum construction, which
          omitted the unmeasurable entry;
  * E5-5  contract 7.1's expected-tier dependency is REMOVED: the rule is
          SCENARIO-INDEPENDENT. Any emitted frozen verdict carrying a non-empty
          ``authenticated_withheld`` channel makes the scenario
          MEASUREMENT_INVALID regardless of scenario id. An evaluator consulting
          a per-scenario expected-tier table would be consulting an
          expected-outcome oracle, which a measuring instrument must not do.
          This lane never had such a table, so the ruling CONFIRMS its
          construction; the scenario-independence is now asserted over all
          twelve registered ids rather than exercised on one.

Erratum 4 rulings carried here:

  * E4-1  the help carve-out is ONE EXACT SINGLE-TOKEN INVOCATION. The
          meta-action is ``--help`` AND NOTHING ELSE: it exits 0 with human text
          on stdout and no result object. ``-h`` is NOT an alias -- it is a CLI
          usage error at exit 2 -- and ``--help`` combined with any other
          argument is a usage error too, because only the LONE help invocation
          is carved out. Help text content and byte length are NOT a parity
          requirement. This SUPERSEDES E3-4's "exactly one flag wide", which was
          ambiguous enough that two lanes measurably diverged on ``-h``;
  * E4-2  the identity boundary is a DIRECT READ of ``DIR/manifest.json``, not
          an enumeration of the bundle first. All five of these are identity not
          established -> exit 1, stdout empty, no result object: the bundle root
          cannot be accessed; ``DIR/manifest.json`` is not found; it is found but
          cannot be opened or read; its bytes do not parse as strict JSON; no
          registered ``scenario_id`` can be obtained. A root manifest that
          cannot be read NEVER yields ``bundle-file-unreadable`` -- a reason
          belongs to a result object, and there is no scenario to name one
          after;
  * E4-3  ``bundle-directory-unreadable`` joins the closed registry -> ERROR,
          exit 3. After identity is established, a bundle traversal that cannot
          complete because a directory cannot be enumerated is THAT reason and
          not ``manifest-invalid``: the latter says the layout is WRONG, this
          says the layout could not be MEASURED. Enumeration succeeding but a
          listed file being absent remains ``bundle-file-missing``; a listed
          regular file whose bytes cannot be read remains
          ``bundle-file-unreadable``;
  * E4-4  ruling ``AD15-IR-7``: duplicate semantic IDs are NOT preflight
          invalidity. There is no bundle-wide preflight gate on duplicate
          ``record_id`` or duplicate ``(chain_id, record_id)``. Such artifacts
          still reach frozen stage evaluation, and a reference lookup yielding
          more than one match is ambiguous under R-A and the frozen resolution
          semantics. This evaluator never picks one and never synthesizes an ID.
          Frozen ``R-10`` is an invariant on the BATCH verifier's own emitted
          verdict set and is not widened into a bundle preflight. The ruling
          CONFIRMS the removal already carried here under A6.

Erratum 3 rulings carried here:

  * E3-1  ruling ``AD15-IR-6``: ``related_artifacts`` is ordered by ascending
          UTF-8 byte order of the MANIFEST-RELATIVE ``artifact_path``, not of
          ``record_id``. ``artifact_path`` always exists, so the request
          envelope -- and with it the ``request_envelope_digest`` harness duty 2
          compares -- is always defined. The pre-erratum resolution here (fail a
          multi-artifact bundle closed when an artifact carried no usable
          ``record_id``) is SUPERSEDED: such an artifact now reaches frozen
          stage 0. ``record_id`` remains ONLY the AIREP semantic
          reference-resolution key and R-A is untouched;
  * E3-2  ``bundle-file-unreadable`` joins the closed registry, and the four
          filesystem reasons are bounded exactly -- path absent or a definite
          ``ENOENT`` on read is ``bundle-file-missing``; present, a permitted
          regular file, but open/read fails or errors is
          ``bundle-file-unreadable``; bytes read but unparseable is
          ``bundle-json-invalid``; bytes read but the digest disagrees is
          ``manifest-digest-mismatch``;
  * E3-3  "a manifest with the wrong name or location" is REMOVED from
          ``manifest-invalid``. NO manifest discovery is performed: identity
          comes only from ``manifest.json`` at the bundle root, and its absence
          is exit 1 with empty stdout. A wrongly-named or misplaced file BESIDE
          a valid root manifest needs no special rule -- it is an unlisted
          regular file, or a listed entry with an invalid ``role``;
  * E3-4  ``--help`` is a CLI META-ACTION, not an evaluation: exit 0, human
          text on stdout, NO result object, ``--bundle`` not required, and the
          contract-8.5 exit table does not apply to it. Every other CLI usage
          error remains exit 2. Its "exactly one flag wide" phrasing is
          SUPERSEDED by E4-1 above, which pins the carve-out to one exact
          single-token invocation.

Erratum 2 rulings carried here:

  * E2-1  every bundle-layout violation is ``manifest-invalid`` -- forbidden
          symlinks, an on-disk regular file ``files[]`` does not list, a
          ``files[]`` entry whose target is not a permitted file kind, a FIFO /
          socket / device or other non-regular non-directory object, and the
          manifest closure / sort / ``role`` / ``path`` / digest-encoding rules.
          Directories are containers only and are never ``files[]`` entries.
          E3-3 removed the wrong-name/location clause from this surface;
  * E2-2  every abnormal frozen run is ``verifier-run-invalid`` -- a
          non-qualifying ``exit 1``, ``exit 2`` or any other impermissible exit,
          ``exit 0`` with empty stdout, ``exit 0`` with non-strict-JSON stdout,
          and ``exit 0`` carrying a malformed / multiple / wrong-shape result.
          ``verifier-not-invocable`` is ONLY a process that could not be spawned
          or executed at all; ``internal-error`` is ONLY this evaluator's own
          unexpected internal fault;
  * E2-3  ruling ``AD15-IR-5``: ``artifact_path`` is required and is the total
          result identity, ``artifact_ref`` is object-or-``null``, ``artifacts[]``
          is ordered by UTF-8 byte order of ``artifact_path``, and a
          ``record_id`` is NEVER synthesized. R-A is unchanged -- reference
          resolution still uses ``record_id`` (additionally ``chain_id`` where
          the reference carries one), and the manifest path never participates
          in it.

Composition, in the contract's own order:

  * section 5    ``manifest.json`` at the bundle root, pinned encoding; symlinks
                 forbidden; every listed file digest-verified BEFORE parsing;
  * section 5.1  the closed section-0 request envelope, RFC 8785 (JCS)
                 serialized; ``request_envelope_digest`` over exactly those
                 bytes; numeric preflight on integral VALUE, not JSON spelling;
  * section 3    frozen-verifier digest assertion before use -- THIS LANE ONLY,
                 at the section-8.2.1 pinned position: immediately after bundle
                 identity and before any other post-identity preflight;
  * section 6    R-A / R-B / R-C, with the section 6.1 applicability matrix;
  * section 7    the Level-1 mapping, plus 7.1 (``authenticated_withheld`` =>
                 MEASUREMENT_INVALID, SCENARIO-INDEPENDENTLY) and 7.2 (the causal
                 guard on frozen ``exit 1``);
  * section 8    one bundle per invocation, one JSON result object, full
                 preflight before any invocation, and the 8.5 exit/stdout table;
  * section 8.6  the ``AD15-IR-13`` THIRTEEN-STAGE pipeline with explicit
                 barriers, the ``(stage_rank, reason_rank_within_stage,
                 canonical_artifact_path [, json_pointer])`` comparison key, and
                 the platform-neutral traversal name key. Discovery order --
                 filesystem traversal, parser reporting, manifest iteration --
                 decides nothing observable;
  * section 8.7  the FOUR-CLASS normative surface, the closed result member set,
                 and ``normative_projection`` / ``projection_bytes`` for
                 aggregate-harness duty 6.

Deliberately NOT implemented:

  * cross-lane envelope-digest equality (ruling ``AD15-IR-4``, contract 5.1 and
    8.1 duty 2). A single Python invocation cannot observe the peer lane's
    digest. It is an aggregate-harness gate and is not part of the 7.2
    preflight-clean condition;
  * the peer lane's verifier digest. Contract 8.2.1: it "does not appear in
    evaluator output at all", not even as an unasserted carried constant. This
    file therefore does not name it;
  * ``head_witness``. Contract 5 pins it absent from every official W1 bundle,
    and the closed manifest ``role`` set has no value that could carry one, so
    the envelope never gains the member;
  * clock inputs. Contract 5 pins official W1 operator-input composition as
    exactly one ``bindings``, one ``revocation``, one ``independence_policy``
    and NO ``clock``;
  * aggregate-harness duty 6 itself. ``normative_projection`` and
    ``projection_bytes`` build and canonicalize THIS lane's own projection,
    which is peer-free; the COMPARISON is the harness's, because it is the only
    party that legitimately sees both trees (contract 4, 8.1 duty 6). The
    per-lane obligation ``W1-BLK-PARITY`` states is that the model SEPARATES THE
    CLASSES, and that is what the block proves.

Exit codes (contract 8.5) -- the dividing line is whether bundle identity was
established, and nothing else:

  0  exactly one result object, ``measurement_status: MEASURED``, Level-1 verdict
  1  stdout empty -- bundle identity could not be established under contract
     5's direct-read identity boundary, and only that (E4-2): bundle root
     inaccessible; root ``manifest.json`` absent; present but unopenable or
     unreadable; not parseable as strict JSON; no registered ``scenario_id``
  2  stdout empty -- CLI usage error, which includes every help spelling and
     combination except the lone ``--help`` meta-action (E4-1)
  3  exactly one result object, MEASUREMENT_INVALID or ERROR, ``level1: null``,
     ``predicates: null``, ``nonmeasurement`` populated

stdlib only; no third-party dependency is added. Diagnostics go to stderr and
are never a source of semantics (contract 8.3, 8.5).

-----------------------------------------------------------------------------
RECORDED AMBIGUITIES -- resolved in the direction the contract determines, and
reported rather than buried. None of them can change the measured result of a
conforming official W1 bundle.

STATUS AFTER ERRATUM 7: EVERY ENTRY BELOW IS CLOSED OR DECIDED. No entry is
OPEN, none awaits a maintainer ruling, and none leaves a machine-observable
behaviour un-pinned. A1, A5 and A8 -- the three this lane still carried as its
own declared ambiguities -- are closed by ``AD15-IR-14``, ``AD15-IR-16`` and
``AD15-IR-17`` respectively, each AGAINST this lane's prior construction; A2 is
closed by E7-19. A12, A16 and A17 are DECIDED positions with their grounds
stated, not unresolved questions.

  A1  CLOSED by Erratum 7 (E7-7, ruling ``AD15-IR-14``), AGAINST this lane's
      construction. Contract 8.1 shows
      ``interop-eval --bundle DIR [operator-input flags]``, but contract 5 pins
      the operator inputs as bundle members addressed by the closed ``role``
      set, and 5.1 says the evaluator "passes through the files the bundle
      ships". Role-derivation is the determinate reading and is what this
      evaluator uses. The three flags are still accepted, but ONLY as a
      consistency assertion, so a flag can never change what is measured.

      THE EXIT BAND IS NOW PINNED. This lane raised a flag/manifest mismatch as
      a CLI usage error at exit 2 with empty stdout, and recorded the objection
      that convicted it: the mismatch is only DETECTABLE after
      ``manifest.json`` has yielded a usable ``scenario_id``, and contract 8.5
      says that once identity is established "the evaluator owes a result object
      naming the scenario it failed on". The ruling divides the two cases
      exactly where this entry was groping for the line -- a CLI SYNTAX error
      (unknown option, missing value, malformed argument) is detectable before
      anything is read and stays exit 2; a SEMANTIC OR PATH MISMATCH against the
      manifest is detectable only after identity and is now reason
      ``operator-input-assertion-mismatch``, ``ERROR``, EXIT 3, with a result
      object naming the scenario. Implemented in
      ``_assert_operator_flags_consistent``, which now raises ``NonMeasurement``
      rather than ``UsageError``. It remains unreachable in an official run,
      which passes no operator-input flags -- and the ruling is pinned anyway,
      because "unreachable in the official run" is precisely the class of gap
      that produced the ``--help`` divergence in Erratum 4 and the entry-kind
      divergence in Erratum 6. NOTHING ABOUT THIS IS OPEN.

  A2  CLOSED by Erratum 7 (E7-19), CONFIRMING this lane's inference and
      REVERSING its stated grounds. Numeric-preflight JSON Pointers are rooted
      at the DOCUMENT carrying the offending number, with the bundle-relative
      path in ``detail``. This entry reasoned to that from operator inputs not
      being envelope members, and then reassured itself that "no harness duty
      compares ``json_pointer`` across lanes" -- which contract 8.7 has now
      made FALSE: ``nonmeasurement.json_pointer`` is a Class-1 cross-lane
      equality field and is inside the duty-6 projection. The conclusion stands
      on the contract's own grounds instead: the check happens before any
      envelope exists, so an envelope-relative pointer would name a document
      that has not been built, and the two bases give DIFFERENT normative
      strings for the same violation (``/profiles/x`` against the artifact
      versus ``/artifact/profiles/x`` against the envelope). NOTHING ABOUT THIS
      IS OPEN.

  A3  CLOSED by Erratum 2. Symlinks and an on-disk file absent from ``files[]``
      are now enumerated normatively under ``manifest-invalid``, which is what
      this lane already did.

  A4  CLOSED by Erratum 2, AGAINST this lane's pre-erratum reading. ``exit 0``
      with unparseable stdout and ``exit 2`` were reported as ``internal-error``
      here; both are now ``verifier-run-invalid``. ``internal-error`` is
      henceforth this evaluator's own fault only.

  A5  CLOSED by Erratum 7 (E7-28, ruling ``AD15-IR-16``), AGAINST this lane's
      construction. This entry recorded the PER-ENTRY shape of
      ``withheld_reasons`` as unpinned and then chose one for itself: a
      per-ARTIFACT object carrying ``artifact_path``, ``artifact_ref`` and the
      two channel arrays inline. That was tolerable while the member sat OUTSIDE
      the parity surface, which is exactly the ground this entry stood on.
      Contract 8.7 now makes ``withheld_reasons`` CLASS-1 cross-lane equality
      data, so an unpinned entry shape is two lanes emitting different objects
      for the same withheld channel and calling it conformance.

      The shape is now pinned and this lane is corrected to it: one entry per
      (artifact, channel, reason), carrying EXACTLY ``artifact_path``,
      ``channel`` -- the frozen channel name verbatim -- and ``reason``, the
      withheld reason string VERBATIM from the frozen verdict and never
      re-worded; the array ordered by that triple in UTF-8 byte order and
      carrying no other member. The array is still emitted unconditionally and
      is ``[]`` when nothing is withheld. See ``withheld_reasons_from_entries``.
      NOTHING ABOUT THIS IS OPEN.

  A6  CLOSED by Erratum 3, AGAINST this lane's pre-erratum resolution. The
      pre-erratum contract ordered ``related_artifacts`` by ``record_id`` while
      ``AD15-IR-5`` had already made ``record_id`` optional, so a multi-artifact
      bundle carrying an unidentifiable artifact had no defined envelope. This
      lane failed such a bundle CLOSED as ``bundle-shape-invalid`` rather than
      invent an order; ruling ``AD15-IR-6`` now keys the envelope on
      ``artifact_path``, which always exists, so the envelope is always defined
      and the fail-closed path is REMOVED. Both defects this lane recorded under
      that resolution are thereby settled: the artifact reaches frozen stage 0
      as ``AD15-IR-5`` requires, and no registry row is used outside its own
      definition.

      Removed with it: the pre-erratum preflight rejection of a bundle carrying
      two artifacts with the SAME ``record_id``. That removal was a reading of
      contract 5 and 8.2.2 -- ``bundle-shape-invalid`` is defined as artifact
      count, family composition or operator-input composition, none of which a
      duplicate ``record_id`` is, while contract 5 pins the opposite treatment
      explicitly -- and Erratum 4 has now CONFIRMED it as ruling ``AD15-IR-7``,
      so it is contract-backed rather than inferred. There is no bundle-wide
      preflight gate on a duplicate ``record_id`` or a duplicate
      ``(chain_id, record_id)``: such artifacts reach frozen stage evaluation,
      and the duplicate is left for R-A to report as a FAIL under the frozen
      resolution semantics ("more than one match is ambiguous and fails closed.
      An evaluator MUST NOT pick one"). Frozen ``R-10`` binds the BATCH
      verifier's own emitted verdict set and is not widened into a bundle rule;
      this evaluator submits each artifact as a separate request.

  A7  CLOSED by ruling ``W1-CORPUS-IR-1`` in ``INTEROP_CORPUS_CONTRACT.md``.
      Contract 5 pins bundle FAMILY COMPOSITION, which can only be checked by
      reading ``artifact_type``, so an artifact broken at stage 0 hard enough to
      lose its ``artifact_type`` would be converted into this evaluator's own
      ``bundle-shape-invalid`` preflight failure. The corpus contract now makes
      the precondition explicit rather than incidental: all twelve official W1
      fixtures MUST retain a usable, schema-consistent ``artifact_type``, and it
      MUST NOT be the mutation target of a mandatory scenario. The composition
      check is therefore kept exactly as it is, and the collision is closed on
      the corpus side where it belongs.

  A8  CLOSED by Erratum 7 (E7-29, ruling ``AD15-IR-17``), PARTLY AGAINST this
      lane. This entry recorded duplicate manifest object members as unpinned
      and then rested the resolution on the fact that "both runtimes decode
      duplicates last-wins by default". The ruling names that reasoning as the
      defect: RELYING ON A RUNTIME DEFAULT IS THE SAME DEFECT AS RELYING ON
      TRAVERSAL ORDER -- it is not a rule, it is a coincidence that two
      implementations currently agree.

      Duplicates are now detected WHILE PARSING, before any value is taken from
      the decoded object, and NO value is ever taken from a duplicated member:

        * a duplicate TOP-LEVEL ``scenario_id`` enters the EXIT-1 band, because
          no registered ``scenario_id`` is DETERMINISTICALLY obtainable -- which
          is already the fifth condition of contract 5's direct-read identity
          boundary, so this adds no new condition to the band. THIS IS THE
          BEHAVIOURAL CORRECTION: this lane took the last-wins value here and
          reported ``manifest-invalid`` at exit 3;
        * a ``scenario_id`` duplicated inside ``files[]`` or any other NESTED
          object does NOT erase a valid top-level identity -- reading it as
          identity-destroying would let a member buried in ``files[]`` suppress
          a result object the evaluator can perfectly well produce, which is the
          exit-1/exit-3 confusion ``AD15-IR-8`` exists to prevent. It is
          ``manifest-invalid`` at STAGE 4, exit 3;
        * ANY other duplicate is likewise ``manifest-invalid`` at stage 4, which
          CONFIRMS the exit band this entry had reasoned to.

      The nesting distinction is what this entry lacked entirely; it treated all
      duplicates alike. See ``_DuplicateRecorder`` and
      ``load_manifest_identity``. The same rule for LISTED ARTIFACT AND
      OPERATOR-INPUT files is E7-22's stage-8 canonicalization row, implemented
      in ``stage_json``: the manifest is read earlier and so could not be
      covered by that stage. NOTHING ABOUT THIS IS OPEN.

  A9  CLOSED by Erratum 3 (E3-2), AGAINST this lane's pre-erratum mapping. A
      listed file that is present and of a permitted kind but UNREADABLE had no
      registry row and was reported here as ``bundle-file-missing``, which says
      something false about the bundle. ``bundle-file-unreadable`` now exists
      and the boundary is exact: path absent, or a definite ``ENOENT`` on read,
      is ``bundle-file-missing``; anything else that fails at open or read time
      is ``bundle-file-unreadable``.

  A10 CLOSED by Erratum 3 (E3-3), CONFIRMING this lane's construction. "A
      manifest with the wrong name or location" is no longer listed under
      ``manifest-invalid``, and no manifest discovery is performed: identity
      comes only from ``manifest.json`` at the bundle root, whose absence is
      exit 1 (contract 8.5). A manifest placed anywhere else is an ordinary
      regular file under the bundle and is caught as an unlisted on-disk file or
      by the closed ``role`` set. No separate code path exists and none is
      invented.

  A11 CLOSED by Erratum 3 (E3-4). ``--help`` is a CLI meta-action, not an
      evaluation: exit 0, human-readable text on stdout, no result object,
      ``--bundle`` not required, and the contract-8.5 exit table does not apply.
      The surface stays unreachable from the aggregate harness, which performs
      exactly twelve ``--bundle`` invocations (8.1) and never invokes it.

      The residual recorded here is CLOSED by Erratum 4 (E4-1). "Exactly one
      flag wide" was ambiguous, and the two lanes measurably diverged on it --
      one reading it as a statement about SPELLINGS and refusing ``-h``, the
      other as a statement about the EXIT-0 LICENCE and accepting it. The
      carve-out is now one exact single-token invocation: ``--help`` alone.

      This lane's ``-h`` behaviour is CONFIRMED (it was already exit 2), and its
      handling of ``--help`` COMBINED WITH OTHER ARGUMENTS is CORRECTED AGAINST
      the pre-erratum construction: registering ``--help`` as an argparse
      ``action="help"`` made ``--help --bundle DIR`` exit 0 with a help screen,
      whereas E4-1 makes only the LONE invocation a meta-action. ``--help`` is
      therefore no longer registered as an option at all; it is matched in
      ``main`` as an exact whole-argv equality, and every other argv reaching
      the parser with ``--help`` in it fails as an unrecognised argument at
      exit 2. Help text content and byte length are not a parity requirement.

  A12 DECIDED, on the frozen contract's own terms -- not an open ambiguity.
      The FROZEN verdict envelope (frozen contract 2) is shape-checked before a
      verdict is trusted -- required members, the closed ``class`` set, the five
      always-present reason arrays, and the closed ``observer_assessment`` set.
      This is E2-2's "wrong-shape result" case and is a shape check ONLY: no
      frozen decision is recomputed and no checked value influences a predicate.
      Frozen 2 does not declare the TOP-LEVEL envelope closed, so an unknown
      top-level member is deliberately tolerated.

      NARROWED by Erratum 7 (``AD15-IR-18``): the NESTED ``artifact_ref`` object
      IS now closed, and a verdict whose ``artifact_ref`` carries any member
      other than ``record_id`` and ``chain_id`` is rejected by this gate as
      ``verifier-run-invalid``. That is a gate THIS contract adds, not a
      re-reading of the frozen one -- the frozen contract permits the extra
      member; W1 does not, because ``artifact_ref`` is a Class-1 cross-lane
      equality field and an open nested object cannot be one.

  A13 CLOSED by Erratum 4. Both limbs were reported OPEN here because E3-2
      bounds its four filesystem reasons over a LISTED FILE and neither I/O
      failure was one:

        (i)  CLOSED by E4-3, AGAINST this lane's pre-erratum mapping. A
             DIRECTORY under the bundle that cannot be enumerated was reported
             as ``manifest-invalid``, with the discomfort recorded here that it
             is not strictly a rule VIOLATION, only an inability to check one.
             The registry now carries ``bundle-directory-unreadable`` for
             exactly that, and the distinction is the one this entry was
             groping for: ``manifest-invalid`` says the layout is WRONG, the new
             reason says the layout could not be MEASURED. E5-3 later split
             the remaining sliver -- an entry whose KIND could not be
             determined -- into ``bundle-entry-uninspectable``; see A14;
        (ii) CLOSED by E4-2, CONFIRMING this lane's construction. The root
             ``manifest.json`` PRESENT but unreadable is exit 1 with no result
             object -- the identity boundary is a direct read, and being
             unopenable or unreadable is now one of its five enumerated
             conditions. The contract also pins the corollary this entry
             reasoned to independently: a root manifest that cannot be read
             NEVER yields ``bundle-file-unreadable``, because a reason belongs
             to a result object and there is no scenario to name one after.
             Unreadable and absent are genuinely indistinguishable here.

  A14 CLOSED by Erratum 5 (E5-3), AGAINST this lane's inferred mapping. The
      case reported here -- enumeration SUCCEEDS, yields an entry, and then the
      entry's KIND cannot be determined because the no-follow stat fails -- was
      mapped to ``bundle-directory-unreadable`` by INFERENCE from E4-3's
      faulty-medium rationale, with the inference recorded as an inference. The
      registry now carries ``bundle-entry-uninspectable`` for exactly that case,
      and the contract's ordering is the one this entry was groping for: each
      row says only what was actually LEARNED and stops there. Enumeration
      succeeded, so ``bundle-directory-unreadable`` is false; the kind was never
      determined, so ``manifest-invalid`` would assert a layout violation that
      could not be established. The mapping here is corrected accordingly.

      REOPENED AND RE-CLOSED by Erratum 6 (E6-1, ``AD15-IR-9``), AGAINST this
      lane's IMPLEMENTATION. E5-3 fixed WHICH REASON the case maps to and this
      lane's mapping was then correct; what stayed unpinned was HOW the kind is
      inspected. This lane read "no-follow inspection" as satisfied by
      ``os.DirEntry.is_symlink()`` / ``is_dir(follow_symlinks=False)`` /
      ``is_file(follow_symlinks=False)``, which on Linux answer from the
      ``d_type`` cached by ``readdir`` WITHOUT any metadata lookup -- so on a
      directory at mode ``0o444`` the kind came back ``(False, False, True)``
      and nothing raised, and the very reason E5-3 had just added was NOT
      REACHED at that point. The peer lane's per-entry lookup failed ``EACCES``
      and reported it. That divergence was MEASURED, not argued, and it is why
      ``entry_kind`` now performs an explicit ``os.lstat`` per enumerated entry.

  A18 DECIDED, and DECLARED because the contract does not order it. Contract
      8.6's stage-6 row lists exactly ONE reason, ``bundle-file-unreadable``,
      while E3-2 separately routes a definite ``ENOENT`` ON READ to
      ``bundle-file-missing``. So stage 6 can produce two reasons and no row
      orders them against each other.

      This lane gives ``bundle-file-missing`` its STAGE-5 mechanism rank, so it
      outranks ``bundle-file-unreadable`` wherever both are live. The ground is
      the barrier model itself: an earlier stage's reason is reported over a
      later stage's regardless of paths, and ``bundle-file-missing`` IS a
      stage-5 reason that merely happens to surface one stage later. Giving it a
      stage-6 rank would let the same reason outrank or be outranked by the same
      peer depending only on which stage noticed it.

      A peer tie-breaking stage 6 by PATH alone would select the other failure
      when the unreadable file sorts first. The cell requires a listed file to
      DISAPPEAR BETWEEN STAGE 5 AND STAGE 6 -- a filesystem race, reachable by
      no corpus bundle and by no official scenario. Recorded rather than left to
      look settled.

  A16 DECIDED. Contract 8.3 types ``verifier_result`` as "the verdict verbatim
      WHEN ONE WAS EMITTED", and ``AD15-IR-15``'s normal-exit row adds "the
      verdict, or ``null`` whenever no verdict exists". Neither enumerates an
      ``exit 0`` whose stdout the RESULT-SHAPE GATE REFUSED. This lane emits
      ``null`` there, on two contract grounds rather than by preference:

        (i)  ``AD15-IR-18`` places "exit 0 whose output the result-shape gate
             rejects" on SOURCE B -- the PRELIMINARY projection path -- which is
             only coherent if no accepted verdict exists to copy from; and
        (ii) ``verifier_result`` is a Class-1 cross-lane equality field (8.7),
             so putting an object the gate has just refused into it would
             smuggle unvalidated frozen output onto the parity surface.

      Unreachable on the mandatory twelve, where every emitted verdict is
      well-formed by construction. Implemented in ``verdict_from_stdout``.

  A17 DECIDED. Contract 8.2 requires ``withheld_reasons`` "emitted
      unconditionally, ``[]`` when nothing is withheld", and ``AD15-IR-10``
      places the 7.1 withheld scan at STAGE 12, after stage 11 completes. On a
      run that ABORTS in stage 11 the scan therefore never runs, and the
      contract does not say whether the member is then ``[]`` or the channels
      actually observed.

      This lane emits THE CHANNELS ACTUALLY OBSERVED, uniformly, in every result
      -- ``MEASURED``, ``MEASUREMENT_INVALID`` and ``ERROR`` alike. Emitting
      ``[]`` would assert an absence that was never measured, which is the
      NOT_MEASURED-as-negative failure the rest of this contract is built to
      prevent; a pre-invocation failure has no entries and so reports ``[]`` as
      a MEASURED emptiness rather than as a default.

      Unreachable on the mandatory twelve: no official scenario produces a
      withheld channel (7.1 -- operator inputs are complete by construction) and
      none produces a stage-11 abort. It is nevertheless a Class-1 field, so it
      is DECLARED rather than left to look settled. Implemented in
      ``withheld_reasons_from_entries`` and ``evaluate_bundle``.

  A15 CLOSED by Erratum 5 (E5-4), AGAINST this lane's construction. The
      conflict reported here -- "exactly two entries" against "never a value
      this lane did not measure", when a frozen file cannot be READ -- is
      resolved by a THIRD option neither clause offered: ``verifier_digests`` is
      ``null``, under a reason of its own, ``frozen-identity-unreadable``. The
      one-entry object this lane emitted is therefore REMOVED: the object is
      exactly two entries or it is ``null``, and no placeholder or omitted entry
      ever appears. The preflight ORDER is pinned with it -- identity, then
      immediately the frozen identity pair, then everything else -- so every
      other post-identity result carries a populated two-entry object.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

EVALUATOR_VERSION = "0.2.6"   # post-Erratum-7 (AD15-IR-12..20, 8.6, 8.7)

#: Contract 8.5 / E4-1: the CLI meta-action is this EXACT argv and no other.
HELP_INVOCATION = ["--help"]

# --------------------------------------------------------------------------
# JCS (RFC 8785) canonicalizer -- loaded from the REPOSITORY, not from PyPI,
# and not copied. The canonical bytes are defined by the repository's own
# canonicalizer at <repo>/spec/airep/v0.1/conformance/jcs.py; resolving it by
# explicit relative path against THIS file keeps the working directory
# irrelevant and adds no third-party dependency (contract 5.1).
# Public API consumed: canonicalize(obj) -> bytes.
# --------------------------------------------------------------------------

JCS_RELPATH = (os.pardir, os.pardir, os.pardir, "v0.1", "conformance", "jcs.py")


def _load_repo_jcs():
    path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), *JCS_RELPATH)
    )
    spec = importlib.util.spec_from_file_location("airep_v0_1_jcs_interop", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load the repository JCS canonicalizer at %s" % path)
    module = importlib.util.module_from_spec(spec)
    # Never drop a __pycache__ next to a repository spec file.
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    if not callable(getattr(module, "canonicalize", None)):
        raise ImportError("%s does not expose canonicalize()" % path)
    return module


jcs = _load_repo_jcs()


# --------------------------------------------------------------------------
# Frozen inputs (contract 3, 8.2.1) -- THIS LANE ONLY
# --------------------------------------------------------------------------

CLASS_VERIFICATION_RELPATH = (os.pardir, os.pardir, "class-verification")

#: Contract 3: "the Python evaluator invokes only verifier_py". Crossing the
#: lanes is forbidden, so this lane knows -- and emits (8.2.1) -- exactly two
#: digests, both of which it recomputes itself. The peer lane's verifier digest
#: is deliberately absent from this file and from every result object.
FROZEN_VERIFIER_RELPATH = ("verifier_py", "class_verifier.py")
FROZEN_CONTRACT_RELPATH = ("CLASS_VERIFIER_CONTRACT.md",)

FROZEN_VERIFIER_SHA256 = \
    "5d08c327648d4bdc83714879be8531c837b991dd474d7ca46397b0ff8c9d01cc"
FROZEN_CONTRACT_SHA256 = \
    "7ecfce56ab576a495816df77e25442b25c1afdb22cc9828e47ba29a565138885"


# --------------------------------------------------------------------------
# Scenario registry and bundle shape (contract 5, 6.1, 8.5)
# --------------------------------------------------------------------------

#: The registered twelve. A manifest naming anything else carries "no usable
#: scenario_id" and is contract-8.5 exit 1.
SINGLE_ARTIFACT_FAMILY: Dict[str, str] = {
    "IOP-P-DEC": "decision",
    "IOP-P-CTL": "control",
    "IOP-P-EXE": "execution",
    "IOP-P-EFF": "effect",
    "IOP-B-DEC": "decision",
    "IOP-B-CTL": "control",
    "IOP-B-EXE": "execution",
    "IOP-B-EFF": "effect",
}
RECONCILIATION_SCENARIOS = (
    "IOP-R-CLEAN", "IOP-R-TOCTOU", "IOP-R-XREF", "IOP-R-INDEP",
)
SCENARIO_IDS = frozenset(SINGLE_ARTIFACT_FAMILY) | frozenset(RECONCILIATION_SCENARIOS)

ARTIFACT_TYPES = ("decision", "control", "execution", "effect")

MANIFEST_FILENAME = "manifest.json"
MANIFEST_VERSION = "1"
MANIFEST_MEMBERS = frozenset({"manifest_version", "scenario_id", "files"})
FILE_ENTRY_MEMBERS = frozenset({"path", "role", "sha256"})
ROLES = ("artifact", "bindings", "independence_policy", "revocation", "clock")

#: Official W1 operator-input composition (contract 5): exactly one each of
#: these, and no ``clock``.
REQUIRED_OPERATOR_ROLES = ("bindings", "independence_policy", "revocation")

#: role -> frozen class-verifier flag.
OPERATOR_FLAG = {
    "bindings": "--bindings",
    "independence_policy": "--independence-policy",
    "revocation": "--revocation",
}

HEX_DIGITS = frozenset("0123456789abcdef")


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
NOT_APPLICABLE = "NOT_APPLICABLE"

MEASURED = "MEASURED"
MEASUREMENT_INVALID = "MEASUREMENT_INVALID"
ERROR = "ERROR"

ACCEPT = "ACCEPT"
REJECT = "REJECT"
RECONCILIATION_MISMATCH = "RECONCILIATION_MISMATCH"
INDEPENDENCE_NOT_ESTABLISHED = "INDEPENDENCE_NOT_ESTABLISHED"

#: Closed reason registry (contract 8.2.2). The value is the
#: ``measurement_status`` that MUST accompany the reason, so the pairing is not
#: left to this implementation.
REASON_STATUS: Dict[str, str] = {
    "manifest-invalid": ERROR,
    "manifest-digest-mismatch": ERROR,
    "bundle-file-missing": ERROR,
    "bundle-file-unreadable": ERROR,
    "bundle-directory-unreadable": ERROR,
    "bundle-entry-uninspectable": ERROR,
    "frozen-identity-unreadable": ERROR,
    "bundle-json-invalid": ERROR,
    "bundle-shape-invalid": ERROR,
    "numeric-preflight-violation": ERROR,
    "verifier-digest-mismatch": ERROR,
    "verifier-not-invocable": ERROR,
    "verifier-run-invalid": ERROR,
    "internal-error": ERROR,
    "operator-input-assertion-mismatch": ERROR,
    "authenticated-withheld": MEASUREMENT_INVALID,
}

#: Ruling ``AD15-IR-13`` (contract 8.6) -- the canonical evaluation pipeline.
#: A stage runs TO COMPLETION over the whole bundle before the next begins, and
#: the FIRST stage that produces a failure determines the reported reason. No
#: later stage overrides an earlier stage's failure. The barriers are the whole
#: point: stages 5, 6 and 7 are separate so that one missing file plus a
#: DIFFERENT file's unreadability plus a THIRD file's digest mismatch reports
#: `bundle-file-missing`, not whichever came first in manifest order.
STAGE_CLI = 1
STAGE_IDENTITY = 2
STAGE_FROZEN_IDENTITY = 3
STAGE_MANIFEST = 4
STAGE_TRAVERSAL = 5
STAGE_READS = 6
STAGE_DIGESTS = 7
STAGE_JSON = 8
STAGE_SHAPE = 9
STAGE_NUMERIC = 10
STAGE_INVOCATION = 11
STAGE_WITHHELD = 12
STAGE_VERDICT = 13

#: Contract 8.6: "Each stage row above lists its reasons IN PRECEDENCE ORDER. A
#: failure of an earlier-listed reason is reported over a later-listed one,
#: REGARDLESS OF PATHS." This is the mechanism component of the comparison key
#: ``(stage_rank, reason_rank_within_stage, canonical_artifact_path
#: [, json_pointer])``. `stage_rank` is already fixed by the barriers, so only
#: the within-stage ordering is tabulated here.
REASON_RANK_WITHIN_STAGE: Dict[str, int] = {
    # stage 5, in the contract's own row order
    "bundle-entry-uninspectable": 0,
    "bundle-directory-unreadable": 1,
    "manifest-invalid": 2,
    "bundle-file-missing": 3,
    # stage 6. `bundle-file-missing` can also surface here -- E3-2 pins a
    # definite ENOENT on READ as "missing", not "unreadable" -- and it keeps its
    # stage-5 rank so that the two never invert.
    "bundle-file-unreadable": 4,
    # stage 7
    "manifest-digest-mismatch": 0,
    # stage 8
    "bundle-json-invalid": 0,
    # stage 9, in the contract's own row order: the bundle's own composition is
    # settled before any assertion an operator makes ABOUT it.
    "bundle-shape-invalid": 0,
    "operator-input-assertion-mismatch": 1,
    # stage 10
    "numeric-preflight-violation": 0,
}

#: Contract 7.2: frozen ``exit 1`` may be read as Level-1 REJECT only for these
#: scenarios (stage-0 / stage-1 invalidity targets), and no other.
EXIT1_REJECT_SCENARIOS = frozenset({"IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"})

MAX_SAFE_INTEGER = 9007199254740991  # 2**53 - 1

# --------------------------------------------------------------------------
# Contract 8.7 -- the normative surface: four classes, a CLOSED result member
# set, and the cross-lane projection harness duty 6 compares.
# --------------------------------------------------------------------------

#: Every closed level of the result object. "A result object carrying an unknown
#: member at any closed level is invalid -- it is NOT silently dropped from the
#: projection. Excluding it would let a lane smuggle an uncompared field into a
#: result that still passed the projection."
RESULT_MEMBERS = frozenset({
    "scenario_id", "measurement_status", "level1", "predicates",
    "nonmeasurement", "artifacts", "withheld_reasons", "verifier_digests",
    "evaluator_version",
})
PREDICATE_MEMBERS = frozenset({"R_A", "R_B", "R_C"})
NONMEASUREMENT_MEMBERS = frozenset({"reason", "detail", "json_pointer"})
ARTIFACT_ENTRY_MEMBERS = frozenset({
    "artifact_path", "artifact_ref", "request_envelope_digest",
    "verifier_exit_code", "verifier_result", "verifier_stderr_digest",
})
WITHHELD_ENTRY_MEMBERS = frozenset({"artifact_path", "channel", "reason"})
VERIFIER_DIGEST_MEMBERS = frozenset({"class_verifier", "class_verifier_contract"})

#: Ruling ``AD15-IR-18``: the non-null ``artifact_ref`` object is CLOSED --
#: exactly ``record_id``, plus ``chain_id`` when and only when the source
#: carried a string one. Enforced at the result-shape gate so that the
#: ``exit 0`` verbatim copy is over a value already known to be closed.
ARTIFACT_REF_MEMBERS = frozenset({"record_id", "chain_id"})

#: Contract 8.7: the closed cross-lane projection is the result object with
#: EXACTLY these removed. Everything else is retained -- including
#: ``verifier_digests.class_verifier_contract``, which is Class-1 data because
#: the two lanes assert the SAME frozen contract.
#:
#:   Class 1 (cross-lane equality)  -- everything the projection retains, plus
#:                                     the process exit code and stdout shape;
#:   Class 2 (lane-local assertion) -- ``verifier_digests.class_verifier`` and
#:                                     ``evaluator_version``;
#:   Class 3 (audit-only evidence)  -- ``verifier_stderr_digest``;
#:   Class 4 (diagnostic-only)      -- ``nonmeasurement.detail``, raw stderr,
#:                                     signal names, stack traces, OS error
#:                                     prose, help text, timings.
PROJECTION_REMOVES = (
    "nonmeasurement.detail",
    "evaluator_version",
    "verifier_digests.class_verifier",
    "artifacts[*].verifier_stderr_digest",
)


# --------------------------------------------------------------------------
# Exceptions -- one per band of the contract-8.5 exit table
# --------------------------------------------------------------------------

class UsageError(Exception):
    """CLI usage error -> exit 2, stdout empty."""


class JsonByteError(Exception):
    """The byte encoding of a JSON file is outside ``AD15-IR-20``'s domain.

    The caller assigns the outcome by WHICH FILE it is, because the two sit on
    opposite sides of the identity boundary: ``manifest.json`` is identity NOT
    established (exit 1, empty stdout), a listed artifact or operator-input file
    is ``bundle-json-invalid`` at stage 8 (exit 3).
    """


class BundleIdentityError(Exception):
    """Bundle identity could not be established -> exit 1, stdout empty.

    Exactly the five conditions of contract 5's DIRECT-READ identity boundary
    (E4-2), which contract 8.5's exit-1 row now points at rather than restates:
    the bundle root cannot be accessed; ``DIR/manifest.json`` is not found; it
    is found but cannot be opened or read; its bytes do not parse as strict
    JSON; or no registered ``scenario_id`` can be obtained from it.
    """


class NonMeasurement(Exception):
    """Identity established, scenario not measured -> exit 3 with a result object.

    ``reason`` is a value from the closed registry; ``measurement_status`` is
    taken FROM that registry rather than chosen here, so the pairing cannot
    drift (contract 8.2.2).
    """

    def __init__(self, reason: str, detail: str,
                 json_pointer: Optional[str] = None,
                 withheld_reasons: Optional[List[dict]] = None,
                 artifacts: Optional[List[dict]] = None) -> None:
        super().__init__(detail)
        if reason not in REASON_STATUS:
            raise KeyError("reason %r is outside the closed registry" % reason)
        if (json_pointer is not None) != (reason == "numeric-preflight-violation"):
            raise ValueError(
                "json_pointer is mandatory for numeric-preflight-violation and "
                "permitted for no other reason")
        self.reason = reason
        self.detail = detail
        self.json_pointer = json_pointer
        self.status = REASON_STATUS[reason]
        self.withheld_reasons = withheld_reasons or []
        #: Contract 8.3.1: an empty array before any invocation; afterwards, an
        #: entry for each invocation actually attempted and only those.
        self.artifacts = artifacts or []
        #: Stamped once the manifest has yielded a usable scenario_id, so the
        #: exit-3 object can name the scenario it failed on (contract 8.5).
        self.scenario_id: Optional[str] = None
        #: Contract 8.2.1 (E5-4): the EXACT TWO digests this lane recomputed,
        #: or ``None`` -- and ``None`` only for ``frozen-identity-unreadable``.
        #: Never a value this lane did not measure, and never one entry.
        self.verifier_digests: Optional[Dict[str, str]] = None


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

#: Ruling ``AD15-IR-20`` -- the JSON byte domain is CLOSED. Before ANY parse,
#: the byte encoding of ``manifest.json`` and of every listed artifact and
#: operator-input JSON file is constrained: UTF-8 only; no UTF-8 BOM; no UTF-16
#: or UTF-32 acceptance; decoding strict and lossless; malformed UTF-8 rejected;
#: replacement decoding with U+FFFD FORBIDDEN; bytes never repaired or
#: transcoded into acceptance.
UTF8_BOM = b"\xef\xbb\xbf"

#: UTF-16 and UTF-32 byte-order marks, longest first so that the two-byte
#: UTF-16LE mark never shadows the four-byte UTF-32LE one.
UTF16_32_BOMS = (
    b"\xff\xfe\x00\x00",   # UTF-32LE
    b"\x00\x00\xfe\xff",   # UTF-32BE
    b"\xff\xfe",             # UTF-16LE
    b"\xfe\xff",             # UTF-16BE
)


def decode_json_bytes(data: bytes) -> str:
    """Decode one JSON file's bytes under ``AD15-IR-20``, or raise
    ``JsonByteError``.

    A BOM is called out separately because it is the case a lenient runtime most
    often accepts silently: one lane strips it and parses, the other rejects,
    and the divergence is invisible until a corpus carries one. Python's
    ``json`` module happens to reject a leading U+FEFF, but relying on that is
    relying on a runtime default -- the same defect ``AD15-IR-17`` exists to
    close one layer down -- so the rejection is stated as a rule here.

    BOM-less UTF-16 and UTF-32 are rejected by the embedded NUL: a raw U+0000
    cannot occur anywhere in conforming JSON text (JSON admits it only as the
    ``\u0000`` escape), so this rejects exactly the transcoded encodings and
    nothing a UTF-8 JSON document can contain. Without it the four BOM-less
    encodings would be refused only INCIDENTALLY, by the JSON parser choking on
    interleaved NULs, which is a coincidence rather than a rule.

    ``bytes.decode("utf-8")`` defaults to ``errors="strict"``: it is lossless
    and never substitutes U+FFFD. That default is asserted here rather than
    assumed.
    """
    if data.startswith(UTF8_BOM):
        raise JsonByteError("bytes begin with a UTF-8 BOM, which is not accepted")
    for bom in UTF16_32_BOMS:
        if data.startswith(bom):
            raise JsonByteError(
                "bytes begin with a UTF-16/UTF-32 byte-order mark; only UTF-8 "
                "is accepted")
    if b"\x00" in data:
        raise JsonByteError(
            "bytes carry a NUL, so they are not UTF-8 JSON text (UTF-16/UTF-32 "
            "input is not accepted, and conforming JSON admits U+0000 only as "
            "an escape)")
    try:
        return data.decode("utf-8")          # strict and lossless; never U+FFFD
    except UnicodeDecodeError as exc:
        raise JsonByteError("bytes are not valid UTF-8: %s" % exc)


def has_unpaired_surrogate(value: Any) -> Optional[str]:
    """Return the RFC 6901 pointer of the first string in ``value`` carrying an
    unpaired surrogate, or ``None``.

    Strict JSON admits an escape such as ``\ud800`` with no pair; RFC 8785
    cannot canonicalize it, because its input requires strings to be valid
    Unicode. Python decodes a well-formed surrogate PAIR into a single
    astral code point, so a paired escape never trips this.

    NO EVALUATOR MAY REPAIR THIS -- not by substituting U+FFFD, not by dropping
    a code unit. Repair is the failure mode being prevented.
    """
    stack: List[Tuple[str, Any]] = [("", value)]
    while stack:
        pointer, node = stack.pop()
        if isinstance(node, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in node):
                return pointer
            continue
        if isinstance(node, dict):
            for key in sorted(node, key=byte_key_lenient, reverse=True):
                child = pointer + "/" + pointer_escape(key)
                if any(0xD800 <= ord(ch) <= 0xDFFF for ch in key):
                    return child
                stack.append((child, node[key]))
            continue
        if isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((pointer + "/" + str(index), node[index]))
    return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def pointer_escape(token: str) -> str:
    """RFC 6901 reference-token escaping."""
    return token.replace("~", "~0").replace("/", "~1")


def byte_key(text: str) -> bytes:
    """Ascending UTF-8 byte order (contract 5.1, 8.4).

    Contract 8.4 scopes this to collections whose identifiers come from JSON
    STRINGS -- ``artifact_path``, manifest ``files[]`` sorting, invocation order
    under ``AD15-IR-12``, request-envelope ordering under 5.1. Filesystem
    directory entries are the one collection it does NOT govern; they use
    ``byte_key_lenient`` below.
    """
    return text.encode("utf-8")


def byte_key_lenient(text: str) -> bytes:
    """Contract 8.6's PLATFORM-NEUTRAL directory-entry name key.

    "Raw bytes" alone is a POSIX-shaped rule and would make this contract
    Linux-only; other platforms expose a Unicode-native directory API and never
    hand back bytes. The key is therefore defined over what the API actually
    provides:

      * lossless raw name bytes -> those bytes, compared as unsigned bytes.
        ``os.fsencode`` recovers them exactly on POSIX, where CPython surfaces
        undecodable bytes through the ``surrogateescape`` handler;
      * a Unicode-native name -> the UTF-8 encoding of the EXACT string
        returned, with NO normalization applied.

    NFC/NFD conversion, case folding, locale-dependent mapping and any
    platform-specific name normalization are FORBIDDEN, here and anywhere else a
    name is compared: a normalizing key makes two byte-distinct entries collide
    on one platform and not on another, which is the cross-platform determinism
    defect ``AD15-IR-9`` exists to close, reintroduced one layer down.

    Where a name is valid UTF-8 and needs no normalization both keys coincide,
    so this WIDENS the ordinary case rather than competing with ``byte_key``.
    """
    try:
        return os.fsencode(text)
    except (UnicodeEncodeError, ValueError):
        # A name that cannot be represented losslessly cannot equal any manifest
        # `path`, which is a JSON string, so it is an unlisted entry. Order it
        # deterministically rather than raising out of a sort.
        return text.encode("utf-8", "backslashreplace")


def dump_json(obj: Any) -> str:
    """Serialize the result object, and NEVER fail on an unpaired surrogate.

    `record_id` / `chain_id` are free-form core strings that may be non-ASCII
    (frozen contract 2), so the default is `ensure_ascii=False`. But a string
    reaching the result object CAN carry an unpaired surrogate -- from a
    `\ud800` escape in a listed file, or in a frozen verdict copied verbatim --
    and such a string has no UTF-8 encoding at all. Encoding it raised
    `UnicodeEncodeError` AFTER bundle identity was established, which left
    EXIT 1 WITH EMPTY STDOUT: the one output contract 8.5 cannot defend against,
    since it is reserved for identity-not-established and only that.

    The fallback re-serializes with `ensure_ascii=True`, which writes the
    surrogate as the JSON escape `\udfff`. THE JSON VALUE IS UNCHANGED -- only
    the serialization differs, and contract 8.7 compares the CANONICAL BYTES OF
    THE VALUE, not this evaluator's choice of serializer. The result object is
    therefore still owed, still emitted, and still exit 3.
    """
    text = json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n"
    return text


def write_result(text: str) -> None:
    """Write the one result object to stdout as UTF-8, whatever the locale.

    ``record_id`` / ``chain_id`` are free-form core strings that MAY be
    non-ASCII (frozen contract 2). Writing them through ``sys.stdout`` in a
    non-UTF-8 locale raises ``UnicodeEncodeError`` AFTER bundle identity is
    established, which would leave exit 1 with empty stdout -- precisely what
    contract 8.5 forbids once identity exists -- and would make contract-8.4
    determinism a property of the operator's environment rather than of the
    bundle. Going through the byte buffer removes the coupling, and the
    explicit flush keeps a pipe-backed stdout from truncating.
    """
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:                     # a text-only stream, e.g. under test
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    buffer.write(text.encode("utf-8"))
    buffer.flush()


def warn(message: str) -> None:
    sys.stderr.write(message.rstrip("\n") + "\n")


def _reject_constant(token: str) -> Any:
    raise ValueError("strict JSON forbids the literal %s" % token)


class _DuplicateRecorder:
    """Object decoding that DETECTS duplicated member names WHILE PARSING.

    Ruling ``AD15-IR-17`` closes recorded ambiguity A8. RFC 8259 permits an
    object to repeat a member name, both runtimes decode such an object
    last-wins by default, and this lane previously RELIED on that default.
    Relying on a runtime default is the same defect as relying on traversal
    order: it is not a rule, it is a coincidence that two implementations
    currently agree.

    So duplicates are detected here, BEFORE any value is taken from the decoded
    object, and NO value is ever taken from a duplicated member -- not
    first-wins, not last-wins, not whatever the parser happens to do. Every
    duplicate is refused, at whichever level it occurs:

      * a duplicate TOP-LEVEL ``scenario_id`` -> the exit-1 band, because no
        registered ``scenario_id`` is DETERMINISTICALLY obtainable. That is
        already the fifth condition of contract 5's direct-read identity
        boundary and adds no new condition to the band;
      * a ``scenario_id`` duplicated inside ``files[]`` or any other NESTED
        object does NOT erase a valid top-level identity -- reading it as
        identity-destroying would let a member buried in ``files[]`` suppress a
        result object the evaluator can perfectly well produce, which is exactly
        the exit-1/exit-3 confusion ``AD15-IR-8`` exists to prevent. It is
        ``manifest-invalid`` at stage 4, exit 3;
      * ANY other duplicate is likewise ``manifest-invalid`` at stage 4.

    ``object_pairs_hook`` is called innermost-first, so the top-level object is
    identified by IDENTITY against the value ``json.loads`` finally returns
    rather than by a depth counter, which nesting inside arrays would defeat.
    """

    def __init__(self) -> None:
        #: (produced object, sorted duplicate member names) per decoded object.
        self.records: List[Tuple[dict, List[str]]] = []

    def __call__(self, pairs: Sequence[Tuple[str, Any]]) -> dict:
        out: Dict[str, Any] = {}
        duplicates: List[str] = []
        for key, value in pairs:
            if key in out and key not in duplicates:
                duplicates.append(key)
            out[key] = value
        if duplicates:
            self.records.append((out, sorted(duplicates)))
        return out

    def split(self, top: Any) -> Tuple[List[str], List[str]]:
        """Return ``(top_level_duplicates, nested_duplicates)`` against ``top``,
        the value the parser finally returned.
        """
        top_level: List[str] = []
        nested: List[str] = []
        for obj, names in self.records:
            if obj is top:
                top_level.extend(names)
            else:
                nested.extend(names)
        return sorted(set(top_level)), sorted(set(nested))

    def any_duplicate(self) -> bool:
        return bool(self.records)


# --------------------------------------------------------------------------
# Numeric preflight (contract 5.1)
# --------------------------------------------------------------------------

def numeric_preflight_all(value: Any,
                          base_pointer: str = "") -> List[Tuple[str, str]]:
    """Return EVERY ``(json_pointer, detail)`` violation in ``value``.

    Contract 8.6 needs the whole set, not the first one found: where a reason
    carries a ``json_pointer`` the tie-break is the ASCENDING UTF-8 BYTE ORDER
    of the pointer string, and a stage that stopped at the first violation could
    not honour it. Two numbers in the same artifact both outside 5.1's envelope
    share a stage, a reason and a path -- the pointer is the only thing left to
    order them by.

    Byte order, not numeric order: ``/a/10`` sorts before ``/a/9`` because ``1``
    precedes ``9`` as a byte. That is deliberate. A rule that compared array
    indices numerically would have to parse them, which invites the two lanes to
    disagree about what is an index.
    """
    out: List[Tuple[str, str]] = []
    stack: List[Tuple[str, Any]] = [(base_pointer, value)]
    while stack:
        pointer, node = stack.pop()
        if isinstance(node, bool):
            continue                      # bool is not a JSON number
        if isinstance(node, int):
            if abs(node) > MAX_SAFE_INTEGER:
                out.append((pointer,
                            "integer-valued number exceeds 2**53-1 in magnitude"))
            continue
        if isinstance(node, float):
            if node != node or node in (float("inf"), float("-inf")):
                out.append((pointer, "number is not finite"))
            elif node.is_integer() and abs(node) > MAX_SAFE_INTEGER:
                out.append((pointer,
                            "integer-valued number exceeds 2**53-1 in magnitude"))
            continue
        if isinstance(node, dict):
            for key in sorted(node, key=byte_key, reverse=True):
                stack.append((pointer + "/" + pointer_escape(key), node[key]))
            continue
        if isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((pointer + "/" + str(index), node[index]))
    return out


def numeric_preflight(value: Any, base_pointer: str = "") -> Optional[Tuple[str, str]]:
    """Return the CANONICALLY SELECTED ``(json_pointer, detail)`` violation, or
    ``None`` when every number in ``value`` is admissible.

    Selection is by ascending UTF-8 byte order of the pointer (contract 8.6),
    not by discovery order: "discovery order may never decide anything
    observable", and ``json_pointer`` is the one locator this contract emits.

    Pinned checks:

      * finite and IEEE-754 representable -- no NaN, no infinity;
      * integer-VALUED numbers: absolute value <= 2**53 - 1.

    The bound is on the MATHEMATICAL VALUE, not on JSON spelling. ``1e20``
    decodes to a float whose value is integral, so it is rejected; ``1.5`` is
    not integer-valued and is judged only by the finiteness rule. Reading the
    bound as a syntax rule would let ``1e20`` through in one lane and not the
    other, which is precisely the divergence this preflight prevents.

    ``1e400`` decodes to ``inf`` and is a NUMERIC violation at STAGE 10 carrying
    its pointer -- NOT a stage-8 ``bundle-json-invalid``. Contract 5's stage-8
    canonicalization table is the unpaired-surrogate and duplicate-member rows
    AND NOTHING ELSE: "the numeric row is ALSO a canonicalization failure, and
    folding it into stage 8 would lose the ``json_pointer`` that 5.1 requires
    and 8.7 makes normative".
    """
    found = numeric_preflight_all(value, base_pointer)
    if not found:
        return None
    return min(found, key=lambda item: byte_key(item[0]))


# --------------------------------------------------------------------------
# Manifest (contract 5) -- identity band, then structural band
# --------------------------------------------------------------------------

class FileEntry:
    __slots__ = ("path", "role", "sha256")

    def __init__(self, path: str, role: str, sha256: str) -> None:
        self.path = path
        self.role = role
        self.sha256 = sha256


class Manifest:
    def __init__(self, scenario_id: str, entries: List[FileEntry]) -> None:
        self.scenario_id = scenario_id
        self.entries = entries

    def by_role(self, role: str) -> List[FileEntry]:
        return [e for e in self.entries if e.role == role]


def load_manifest_identity(bundle_dir: str) -> Tuple[dict, str, List[str]]:
    """Establish bundle identity, or raise ``BundleIdentityError`` (exit 1).

    THE IDENTITY BOUNDARY IS A DIRECT READ (Erratum 4, E4-2). Identity comes
    from reading the bytes of ``DIR/manifest.json`` DIRECTLY -- the bundle is
    NOT enumerated first, and nothing here touches any other path. All five of
    the following are identity not established -> exit 1, stdout empty, no
    result object: the bundle root cannot be accessed; ``DIR/manifest.json`` is
    not found; it is found but cannot be opened or read; its bytes do not parse
    as strict JSON; no registered ``scenario_id`` can be obtained from it. The
    first three all surface as ``OSError`` from the one ``open`` below, which is
    why they need no separate probe: an inaccessible root, an absent file and an
    unreadable file are indistinguishable to this evaluator precisely because
    none of them yields an identity.

    Everything downstream of this function is exit 3 with a named reason --
    including a duplicated manifest member, which is parseable strict JSON and
    therefore does NOT withhold identity (ambiguity A8).

    NO MANIFEST DISCOVERY IS PERFORMED (Erratum 3, E3-3). Identity comes only
    from ``manifest.json`` at the bundle ROOT; nothing else is looked for under
    any other name or in any other directory. Its absence is exit 1 -- never
    ``manifest-invalid``, which would require an identity this evaluator does
    not have. A wrongly-named or misplaced file sitting BESIDE a valid root
    manifest needs no rule of its own: it is an unlisted regular file, or a
    listed entry with an invalid ``role``, and the ordinary layout rules make it
    ``manifest-invalid`` at exit 3.

    A SYMLINKED root manifest is deliberately NOT diverted here. E2-1 enumerates
    "a forbidden symlink anywhere under the bundle" under ``manifest-invalid``,
    and the E4-2 identity boundary is a DIRECT READ: a link whose target opens
    and parses yields an identity, so none of the five conditions is met and the
    exit-1 band is not entered. Identity is therefore taken from the link's
    target and ``stage_traversal`` reports the symlink as ``manifest-invalid`` at
    exit 3, so the harness receives a result object naming the scenario. (The
    argument previously rested on the exit-1 band being "exactly three
    conditions"; that count is superseded, the conclusion is not.)
    """
    path = os.path.join(bundle_dir, MANIFEST_FILENAME)
    try:
        raw = read_manifest_bytes(path)
    except OSError as exc:
        # E4-2: root inaccessible, manifest absent, and manifest present but
        # unopenable or unreadable are three of the five identity conditions and
        # all exit 1. A ROOT MANIFEST THAT CANNOT BE READ NEVER YIELDS
        # `bundle-file-unreadable`: the root manifest is excluded from `files[]`
        # by contract 5, and more fundamentally a reason belongs to a result
        # object, of which there is none here because there is no scenario to
        # name one after. This closes recorded ambiguity A13(ii) in favour of
        # what this lane already did.
        raise BundleIdentityError("manifest unreadable at %s: %s" % (path, exc))
    # AD15-IR-20: the byte domain is closed BEFORE any parse, and for
    # `manifest.json` a violation is identity NOT ESTABLISHED -- exit 1, empty
    # stdout. The two sides of the identity boundary carry different outcomes
    # for the same byte defect, which is why the check is assigned by file.
    try:
        text = decode_json_bytes(raw)
    except JsonByteError as exc:
        raise BundleIdentityError("manifest byte encoding: %s" % exc)
    recorder = _DuplicateRecorder()
    try:
        doc = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=recorder,
        )
    except ValueError as exc:
        raise BundleIdentityError("manifest is not parseable as strict JSON: %s" % exc)
    if not isinstance(doc, dict):
        raise BundleIdentityError("manifest is not a JSON object")
    top_level_duplicates, nested_duplicates = recorder.split(doc)
    if "scenario_id" in top_level_duplicates:
        # AD15-IR-17: ONLY a duplicate TOP-LEVEL `scenario_id` enters the exit-1
        # band -- no registered scenario_id is DETERMINISTICALLY obtainable,
        # which is already contract 5's fifth identity condition. Taking the
        # parser's last-wins value here would be exactly the runtime-default
        # reliance the ruling forbids.
        raise BundleIdentityError(
            "manifest repeats the top-level member scenario_id, so no "
            "registered scenario_id is deterministically obtainable")
    scenario_id = doc.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in SCENARIO_IDS:
        raise BundleIdentityError(
            "manifest carries no usable scenario_id from the registered twelve")
    # A nested duplicate -- including a nested `scenario_id` -- does NOT erase a
    # valid top-level identity. It is reported at stage 4 against the scenario
    # this read has just established.
    return doc, scenario_id, sorted(set(top_level_duplicates) | set(nested_duplicates))


def read_manifest_bytes(path: str) -> bytes:
    """Read the ROOT manifest, raising ``OSError`` verbatim.

    A named seam, so E4-2's third identity condition -- present but unopenable
    or unreadable -- can be exercised deterministically rather than only through
    filesystem permissions, which are not portable.
    """
    with open(path, "rb") as handle:
        return handle.read()


def _bad_manifest(detail: str) -> NonMeasurement:
    return NonMeasurement("manifest-invalid", detail)


def validate_manifest(doc: dict, scenario_id: str,
                      duplicates: Sequence[str] = ()) -> Manifest:
    """Apply the pinned manifest encoding (contract 5). Failures are
    ``manifest-invalid`` at exit 3 -- identity is already established, and
    Erratum 2 makes that reason cover the whole manifest-rule surface.
    """
    if duplicates:
        # AD15-IR-17: every duplicate that did not destroy identity is
        # `manifest-invalid` at STAGE 4, exit 3 -- a nested `scenario_id`
        # included. Identity was established, so a result object is owed
        # (`AD15-IR-8`). No value has been taken from any duplicated member.
        raise _bad_manifest(
            "manifest repeats object member name(s), which is refused rather "
            "than resolved by any parser default: %s"
            % ", ".join(sorted(duplicates)))
    extra = sorted(set(doc) - MANIFEST_MEMBERS)
    if extra:
        raise _bad_manifest("manifest carries unknown member(s): %s" % ", ".join(extra))
    missing = sorted(MANIFEST_MEMBERS - set(doc))
    if missing:
        raise _bad_manifest("manifest is missing member(s): %s" % ", ".join(missing))
    if doc["manifest_version"] != MANIFEST_VERSION:
        raise _bad_manifest(
            "manifest_version is %r, not the string %r"
            % (doc["manifest_version"], MANIFEST_VERSION))
    raw_files = doc["files"]
    if not isinstance(raw_files, list):
        raise _bad_manifest("files is not an array")
    # An EMPTY `files` array is deliberately NOT rejected here. Contract 5 pins
    # closure, sort, `role`, `path` and digest encoding, and nowhere requires
    # `files` to be non-empty, so a `manifest-invalid` rule of this lane's own
    # invention would put two conforming lanes on different
    # `nonmeasurement.reason` values for the same bundle without changing any
    # Level-1 value -- the Erratum-2 gap-2 shape that no aggregate duty can see.
    # Bundle shape owns it instead: zero artifacts fails the contract-5 count
    # for every scenario group, as `bundle-shape-invalid`.

    entries: List[FileEntry] = []
    seen: Dict[str, None] = {}
    for index, raw in enumerate(raw_files):
        if not isinstance(raw, dict):
            raise _bad_manifest("files[%d] is not an object" % index)
        unknown = sorted(set(raw) - FILE_ENTRY_MEMBERS)
        if unknown:
            raise _bad_manifest(
                "files[%d] carries unknown member(s): %s" % (index, ", ".join(unknown)))
        absent = sorted(FILE_ENTRY_MEMBERS - set(raw))
        if absent:
            raise _bad_manifest(
                "files[%d] is missing member(s): %s" % (index, ", ".join(absent)))
        path, role, digest = raw["path"], raw["role"], raw["sha256"]
        if not isinstance(path, str) or not path:
            raise _bad_manifest("files[%d].path is not a non-empty string" % index)
        _validate_manifest_path(index, path)
        if path in seen:
            raise _bad_manifest("files lists path %r more than once" % path)
        seen[path] = None
        if role not in ROLES:
            raise _bad_manifest("files[%d].role %r is outside the closed set" % (index, role))
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(c not in HEX_DIGITS for c in digest):
            raise _bad_manifest(
                "files[%d].sha256 is not exactly 64 lowercase hex characters "
                "with no prefix" % index)
        entries.append(FileEntry(path, role, digest))

    paths = [e.path for e in entries]
    if paths != sorted(paths, key=byte_key):
        raise _bad_manifest("files is not sorted ascending by path in UTF-8 byte order")
    return Manifest(scenario_id, entries)


#: Ruling ``AD15-IR-19`` -- ``segment = 1*(ALPHA / DIGIT / "." / "_" / "-")``.
#: The set is closed and LEXICAL, so the rejections the ruling enumerates
#: separately -- backslash, colon or drive prefix, NUL or control character,
#: non-ASCII character -- all follow from membership rather than from four
#: further tests that could drift apart from it.
PATH_SEGMENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._-"
)


def _validate_manifest_path(index: int, path: str) -> None:
    """Ruling ``AD15-IR-19`` -- the path grammar is LEXICAL and CLOSED.

    "Bundle-relative and normalized" named a property without saying how to test
    it, and "normalized" invites an evaluator to normalize a path INTO
    acceptance. The grammar is exact::

        path    = segment *("/" segment)
        segment = 1*(ALPHA / DIGIT / "." / "_" / "-")

    with all of: segment must not equal "." or ".."; no leading slash; no
    trailing slash; no empty segment; no doubled slash; no backslash; no colon
    or drive prefix; no NUL or control character; no non-ASCII character; NO
    NORMALIZATION OR REPAIR.

        A path is accepted only when its ORIGINAL JSON STRING already satisfies
        the canonical grammar. An evaluator NEVER normalizes a path into
        acceptance.

    Nothing here calls ``os.path.normpath``, ``os.path.abspath``,
    ``unicodedata.normalize`` or any case mapping. The string is tested as
    decoded and is otherwise untouched.

    A violation is ``manifest-invalid`` at STAGE 4 -- a property of the manifest
    DOCUMENT, testable before the filesystem is consulted. An unpaired surrogate
    in a path falls out of the ASCII-only rule for the same reason: it does not
    encode to well-formed UTF-8, so it cannot denote any filesystem name, and it
    fails on the manifest's own terms before the disk is read.
    """
    if path == "":
        raise _bad_manifest("files[%d].path is the empty string" % index)
    if path.startswith("/"):
        raise _bad_manifest(
            "files[%d].path %r has a leading slash" % (index, path))
    if path.endswith("/"):
        raise _bad_manifest(
            "files[%d].path %r has a trailing slash" % (index, path))
    for segment in path.split("/"):
        if segment == "":
            raise _bad_manifest(
                "files[%d].path %r carries an empty segment (a doubled slash)"
                % (index, path))
        if segment == "." or segment == "..":
            raise _bad_manifest(
                "files[%d].path %r carries a %r segment" % (index, path, segment))
        bad = [ch for ch in segment if ch not in PATH_SEGMENT_CHARS]
        if bad:
            raise _bad_manifest(
                "files[%d].path %r carries character(s) outside the closed "
                "AD15-IR-19 segment set: %s"
                % (index, path, ", ".join(repr(ch) for ch in sorted(set(bad)))))
    if path == MANIFEST_FILENAME:
        raise _bad_manifest(
            "files lists the root %s, which it must exclude" % MANIFEST_FILENAME)


# --------------------------------------------------------------------------
# Bundle file set (contract 5)
# --------------------------------------------------------------------------

def _stage_select(candidates: List[Tuple[int, str, "NonMeasurement"]]) -> Optional["NonMeasurement"]:
    """Contract 8.6's within-stage comparison key, applied to one stage's
    complete candidate set.

    "Within a stage, precedence is by MECHANISM first, then by PATH." Mechanism
    is ``REASON_RANK_WITHIN_STAGE`` -- each stage row lists its reasons in
    precedence order, and an earlier-listed reason is reported over a
    later-listed one REGARDLESS OF PATHS. Path is the ascending-first offending
    path; a PATHLESS whole-bundle violation uses the EMPTY BYTE STRING as its
    internal key, which is what makes the ordering total in that case -- no real
    path is empty, so it never collides. The internal key is not emitted.

    Discovery order decides nothing: every candidate is collected before any is
    selected, so filesystem traversal order, parser reporting order and
    iteration order over the manifest are all irrelevant to the reported reason.
    """
    if not candidates:
        return None
    best = min(candidates,
               key=lambda item: (REASON_RANK_WITHIN_STAGE[item[2].reason],
                                 byte_key_lenient(item[1])))
    return best[2]


def stage_traversal(bundle_dir: str, manifest: Manifest) -> List[str]:
    """STAGE 5 -- canonical traversal: entry kind (``AD15-IR-9``), layout
    closure, and listed-file presence. Runs TO COMPLETION over the whole bundle
    before stage 6 begins.

    Reasons, in the contract's own precedence order:
    ``bundle-entry-uninspectable`` · ``bundle-directory-unreadable`` ·
    ``manifest-invalid`` · ``bundle-file-missing``.

    Symbolic links are forbidden ANYWHERE under the bundle -- including one
    whose target resolves inside it -- because a digest over a link's target is
    not a digest over the bundle's own bytes.

    Runs only AFTER identity is established (E4-2), and by ruling ``AD15-IR-8``
    (E5-1) nothing here can retroactively unestablish it: a bundle directory at
    mode ``0o111`` lets the root manifest open while ``readdir`` fails
    ``EACCES``, so the result is ``bundle-directory-unreadable`` at exit 3,
    never exit 1.

    TRAVERSAL ORDER IS NEVER THE OPERATING SYSTEM'S. ``readdir`` order is
    unspecified and varies by filesystem, so every directory's entries are
    sorted -- by the platform-neutral name key -- before that directory is
    inspected or descended into. And because the whole stage is collected before
    any candidate is selected, even that ordering cannot decide the reported
    reason.
    """
    candidates: List[Tuple[int, str, NonMeasurement]] = []
    found: List[str] = []

    def walk(directory: str, prefix: str) -> None:
        # E4-3: enumeration failure is NOT a layout violation. `manifest-invalid`
        # says the layout is WRONG; this says the layout could not be MEASURED.
        try:
            entries = scan_directory(directory)
        except OSError as exc:
            candidates.append((STAGE_TRAVERSAL, prefix, NonMeasurement(
                "bundle-directory-unreadable",
                "bundle traversal could not complete: directory %r could not be "
                "enumerated: %s" % (prefix or ".", exc))))
            return
        for entry in entries:
            rel = entry.name if not prefix else prefix + "/" + entry.name
            try:
                is_link, is_dir, is_file = entry_kind(entry)
            except OSError as exc:
                # E5-3 / AD15-IR-9. The entry NAME was obtained, so enumeration
                # SUCCEEDED and `bundle-directory-unreadable` is false; the KIND
                # was never determined, so `manifest-invalid` would assert a
                # layout violation that is precisely what could not be
                # established. Each row says only what was actually learned.
                candidates.append((STAGE_TRAVERSAL, rel, NonMeasurement(
                    "bundle-entry-uninspectable",
                    "bundle entry %r was enumerated, but its filesystem kind "
                    "could not be determined: %s" % (rel, exc))))
                continue
            if is_link:
                candidates.append((STAGE_TRAVERSAL, rel, _bad_manifest(
                    "bundle carries a symbolic link at %r" % rel)))
                continue
            if is_dir:
                walk(entry.path, rel)
                continue
            if not is_file:
                candidates.append((STAGE_TRAVERSAL, rel, _bad_manifest(
                    "bundle carries a non-regular, non-directory entry at %r" % rel)))
                continue
            if rel == MANIFEST_FILENAME:
                continue
            found.append(rel)

    walk(bundle_dir, "")
    found.sort(key=byte_key_lenient)

    listed = {e.path for e in manifest.entries}
    for rel in found:
        # A directory-entry name that is not valid UTF-8, or that cannot be
        # represented losslessly, can never equal a manifest `path` -- which is
        # a JSON string -- so it lands here as an ordinary unlisted entry, with
        # its sort position already well defined by the platform-neutral key.
        if rel not in listed:
            candidates.append((STAGE_TRAVERSAL, rel, _bad_manifest(
                "bundle carries a file absent from files[]: %r" % rel)))

    present = set(found)
    for entry in manifest.entries:
        if entry.path in present:
            continue
        # Erratum 2 separates the two cases the pre-erratum code conflated. A
        # files[] entry whose target EXISTS but is not a permitted file kind --
        # a directory being the ordinary case, since directories are containers
        # only -- is a LAYOUT violation and so `manifest-invalid`. Only a target
        # that is not there at all is `bundle-file-missing`.
        full = os.path.join(bundle_dir, *entry.path.split("/"))
        if os.path.isdir(full):
            candidates.append((STAGE_TRAVERSAL, entry.path, _bad_manifest(
                "files[] entry %r names a directory; directories are containers "
                "only and are never files[] entries" % entry.path)))
        elif os.path.exists(full):
            candidates.append((STAGE_TRAVERSAL, entry.path, _bad_manifest(
                "files[] entry %r names an object that is not a permitted file "
                "kind" % entry.path)))
        else:
            candidates.append((STAGE_TRAVERSAL, entry.path, NonMeasurement(
                "bundle-file-missing",
                "files[] lists %r but no such regular file is present"
                % entry.path)))

    selected = _stage_select(candidates)
    if selected is not None:
        raise selected
    return found

def scan_directory(directory: str) -> List[os.DirEntry]:
    """Enumerate one directory, raising ``OSError`` verbatim.

    A named seam, so the E4-3 boundary between `bundle-directory-unreadable` and
    the layout reasons can be exercised deterministically rather than only
    through filesystem permissions, which are not portable.
    """
    with os.scandir(directory) as scan:
        return sorted(scan, key=lambda e: byte_key_lenient(e.name))


def entry_kind(entry: os.DirEntry) -> Tuple[bool, bool, bool]:
    """Classify one enumerated entry as ``(symlink, directory, regular file)``
    by an AUTHORITATIVE NO-FOLLOW METADATA LOOKUP, raising ``OSError`` verbatim.

    Ruling ``AD15-IR-9`` (E6-1) pins what contract 8.2.2's first boundary row
    previously left as "``lstat`` OR EQUIVALENT". A type hint obtained DURING
    ENUMERATION -- ``d_type`` from ``readdir``, ``Dirent.isFile()``,
    ``os.DirEntry.is_file()`` and their equivalents -- is NOT kind evidence on
    its own: those APIs may answer from a value the directory read happened to
    carry, WITHOUT performing any metadata lookup on the entry itself, and they
    can only answer that way on filesystems that populate it.

    This lane's pre-ruling construction did exactly that, and the divergence was
    MEASURED rather than argued: on a directory that is readable but not
    searchable (mode ``0o444``) holding one file, ``os.DirEntry`` answered
    ``(is_symlink=False, is_dir=False, is_file=True)`` from the cached ``d_type``
    and raised NOTHING, so ``bundle-entry-uninspectable`` was never reached at
    that point, while the peer lane's per-entry no-follow lookup failed
    ``EACCES`` and reported it. Same bundle, same kernel, two different reasons.

    So the lookup is now explicit and per entry. ``os.lstat`` is ``lstat(2)``: a
    fresh syscall against the entry itself, never a cached ``readdir`` value, and
    it does not follow a final-component symlink -- which is what makes a symlink
    OBSERVABLE here rather than silently resolved to its target. The kind is
    derived from the returned ``st_mode`` alone. Any ``OSError`` propagates
    verbatim and the caller maps it to ``bundle-entry-uninspectable``, because
    the entry NAME was obtained while its KIND was never established.

    The defect this closes is CROSS-PLATFORM DETERMINISM, not semantics: no
    mandatory scenario's Level-1 value moves. What moves is that the reason no
    longer depends on whether the medium the corpus happens to sit on populates
    ``d_type`` -- a rule that holds on ``ext4`` and fails where the kernel
    returns ``DT_UNKNOWN`` is not a determinism rule.
    """
    mode = os.lstat(entry.path).st_mode
    return (stat.S_ISLNK(mode), stat.S_ISDIR(mode), stat.S_ISREG(mode))


def stage_scandirectory_sort_key(name: str) -> bytes:
    """Kept as a named seam so the platform-neutral key is testable directly."""
    return byte_key_lenient(name)


def stage_reads(bundle_dir: str, manifest: Manifest) -> Dict[str, bytes]:
    """STAGE 6 -- ALL listed-file reads, as one barrier.

    Contract 8.6: "Stages 6 and 7 are separate so that a bundle with one
    unreadable file and a DIFFERENT file's digest mismatch reports
    ``bundle-file-unreadable``: every read completes before any digest is
    checked. An implementation validating each path end-to-end in manifest order
    would report the mismatch instead, and both readings satisfied the old
    'complete the whole bundle preflight first'."

    E3-2 bounds the boundary exactly: the file was present and of a permitted
    kind when stage 5 ran, so a DEFINITE ``ENOENT`` here is a file that went
    away and stays ``bundle-file-missing``; every other open/read failure is
    ``bundle-file-unreadable``, which says the true thing -- the medium failed,
    the bundle is not incomplete. ``bundle-file-missing`` keeps its stage-5
    mechanism rank so the two can never invert.
    """
    candidates: List[Tuple[int, str, NonMeasurement]] = []
    contents: Dict[str, bytes] = {}
    for entry in manifest.entries:
        full = os.path.join(bundle_dir, *entry.path.split("/"))
        try:
            contents[entry.path] = read_bundle_file(full)
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ENOENT:
                candidates.append((STAGE_READS, entry.path, NonMeasurement(
                    "bundle-file-missing",
                    "files[] lists %r but it is no longer present: %s"
                    % (entry.path, exc))))
            else:
                candidates.append((STAGE_READS, entry.path, NonMeasurement(
                    "bundle-file-unreadable",
                    "%r is present and a permitted regular file, but its bytes "
                    "could not be read: %s" % (entry.path, exc))))
    selected = _stage_select(candidates)
    if selected is not None:
        raise selected
    return contents


def stage_digests(manifest: Manifest, contents: Dict[str, bytes]) -> None:
    """STAGE 7 -- ALL digest checks, as one barrier, BEFORE anything is parsed.

    This is the layer that protects artifact provenance (contract 5.1 Layer 1),
    and it is what makes "the bundle's own operator-input bytes" an auditable
    statement rather than an assumption.
    """
    candidates: List[Tuple[int, str, NonMeasurement]] = []
    for entry in manifest.entries:
        measured = sha256_hex(contents[entry.path])
        if measured != entry.sha256:
            candidates.append((STAGE_DIGESTS, entry.path, NonMeasurement(
                "manifest-digest-mismatch",
                "%r: manifest says %s, bundle bytes measure %s"
                % (entry.path, entry.sha256, measured))))
    selected = _stage_select(candidates)
    if selected is not None:
        raise selected


def read_bundle_file(full_path: str) -> bytes:
    """Read one listed bundle file, raising ``OSError`` verbatim.

    A named seam, so the E3-2 boundary between ``bundle-file-missing`` and
    ``bundle-file-unreadable`` can be exercised deterministically rather than
    only through filesystem permissions, which are not portable.
    """
    with open(full_path, "rb") as handle:
        return handle.read()


def stage_json(manifest: Manifest, contents: Dict[str, bytes]) -> Dict[str, Any]:
    """STAGE 8 -- JSON byte domain, parsing, then contract 5's TWO stage-8
    canonicalization rules. Every failure is ``bundle-json-invalid``.

    A document can parse cleanly and still have NO CANONICAL FORM, and that is
    checked HERE, never at envelope assembly. RFC 8785 constrains its input in
    three ways beyond strict JSON syntax; two of them belong to this stage and
    the third does not:

    ======================================  =========================  ======
    RFC 8785 input requirement              Violation                  Stage
    ======================================  =========================  ======
    strings are valid Unicode               an unpaired surrogate      8
    objects have no duplicate member names  the same name twice        8
    numbers are IEEE-754 doubles            e.g. ``1e400``             10
    ======================================  =========================  ======

    THAT TABLE IS THE WHOLE OF STAGE 8's CANONICALIZABILITY QUESTION -- the
    first two rows and nothing else. It is NOT shorthand for "whatever RFC 8785
    rejects": the numeric row is ALSO a canonicalization failure, and folding it
    into stage 8 would lose the ``json_pointer`` that 5.1 requires and 8.7 makes
    normative. So ``1e400`` is deliberately allowed THROUGH this stage and is
    reported by stage 10 as ``numeric-preflight-violation`` with its pointer.

    NO EVALUATOR MAY REPAIR ANY OF THESE. Not by substituting U+FFFD, not by
    dropping a code unit, not by taking the first or the last of two duplicate
    members. Repair is the failure mode being prevented: left to the runtime,
    one lane raises, another silently canonicalizes ``{"k":1}`` where a third
    canonicalizes ``{"k":2}``, and the two produce DIFFERENT
    ``request_envelope_digest`` values over the same file while both reporting
    success -- the digest would then attest to something the file did not say.
    """
    candidates: List[Tuple[int, str, NonMeasurement]] = []
    parsed: Dict[str, Any] = {}
    for entry in manifest.entries:
        data = contents[entry.path]
        # AD15-IR-20, applied to a LISTED file: `bundle-json-invalid` at stage
        # 8, exit 3 -- the other side of the identity boundary from the root
        # manifest, which is exit 1 for the same byte defect.
        try:
            body = decode_json_bytes(data)
        except JsonByteError as exc:
            candidates.append((STAGE_JSON, entry.path, NonMeasurement(
                "bundle-json-invalid",
                "%r byte encoding: %s" % (entry.path, exc))))
            continue
        recorder = _DuplicateRecorder()
        try:
            # STRICT. `NaN`, `Infinity` and `-Infinity` are NOT JSON tokens --
            # RFC 8259 has no such literals -- so a file carrying one is "not
            # parseable JSON" and is `bundle-json-invalid` HERE, at stage 8.
            #
            # This is NOT the AD15-IR-20 numeric row, which is about `1e400`:
            # that is perfectly ordinary JSON SYNTAX whose VALUE is outside
            # 5.1's envelope, so it parses cleanly and is caught at stage 10
            # WITH its `json_pointer`. The two cases look alike only because
            # CPython decodes both to `inf`.
            #
            # Python's `json` accepts the three literals by DEFAULT, which is a
            # runtime leniency, not a rule -- the same defect AD15-IR-17 and
            # AD15-IR-20 close elsewhere. Left to that default this lane
            # reported `numeric-preflight-violation` WITH a pointer where a
            # strict parser reports `bundle-json-invalid` WITHOUT one; both
            # `nonmeasurement.reason` and `nonmeasurement.json_pointer` are
            # Class-1 cross-lane equality fields inside the duty-6 projection,
            # so that is divergent evidence over identical bytes.
            value = json.loads(body, parse_constant=_reject_constant,
                               object_pairs_hook=recorder)
        except ValueError as exc:
            candidates.append((STAGE_JSON, entry.path, NonMeasurement(
                "bundle-json-invalid",
                "%r is not parseable JSON: %s" % (entry.path, exc))))
            continue
        if recorder.any_duplicate():
            names = sorted({name for _obj, names in recorder.records
                            for name in names})
            candidates.append((STAGE_JSON, entry.path, NonMeasurement(
                "bundle-json-invalid",
                "%r repeats object member name(s), so it has no RFC 8785 "
                "canonical form and is refused rather than resolved by any "
                "parser default: %s" % (entry.path, ", ".join(names)))))
            continue
        pointer = has_unpaired_surrogate(value)
        if pointer is not None:
            candidates.append((STAGE_JSON, entry.path, NonMeasurement(
                "bundle-json-invalid",
                # `%r`, NEVER `%s`: an unpaired surrogate can occur in a member
                # NAME, so the POINTER carries it too. Interpolating it raw put
                # a lone surrogate into `detail` and the result object then
                # could not be encoded at all -- see `dump_json`.
                "%r carries an unpaired surrogate at %r, so it has no RFC 8785 "
                "canonical form; substitution or repair is forbidden"
                % (entry.path, pointer or "the document root"))))
            continue
        parsed[entry.path] = value
    selected = _stage_select(candidates)
    if selected is not None:
        raise selected
    return parsed


# --------------------------------------------------------------------------
# Bundle shape (contract 5)
# --------------------------------------------------------------------------

def artifact_ref_from_artifact(value: Any) -> Optional[Dict[str, str]]:
    """Ruling ``AD15-IR-18`` -- ONE closed ``artifact_ref`` projection, TOTAL
    over every JSON value.

    Contract 8.7 makes ``artifact_ref`` a cross-lane equality field, and it was
    previously described only as "the structured reference when a usable
    ``record_id`` exists", which left two lanes to invent the same object from
    the same artifact by luck. The function is exact::

        1. If value is not a JSON object, return null.
        2. If value.record_id is not a JSON string, return null.
        3. Otherwise return an object containing exactly:
             "record_id": value.record_id
           and, only when value.chain_id is a JSON string:
             "chain_id": value.chain_id
        4. A missing or non-string chain_id is OMITTED, never null.
        5. Empty strings remain strings; the evaluator does not add a
           minLength rule absent from the frozen schema.
        6. No coercion, Unicode normalization, case mapping, repair,
           synthesis, or stringification is permitted.

    Step 4 matters because an omitted member and a ``null`` member are different
    JSON values and therefore different RFC 8785 canonical bytes. Step 6
    restates ``AD15-IR-5``'s absolute bar on synthesizing a ``record_id``,
    extended to every form of quiet repair.

    STEP 5 CORRECTS THIS LANE. Its pre-erratum projection treated an EMPTY
    ``record_id`` as no usable identity and returned ``null`` -- a ``minLength``
    rule of its own invention, absent from the frozen schema, and now the kind
    of quiet repair step 6 forbids.

    ``bool`` is deliberately not special-cased: in Python a ``bool`` is not a
    ``str``, so step 2 already rejects it.
    """
    if not isinstance(value, dict):
        return None
    record_id = value.get("record_id")
    if not isinstance(record_id, str):
        return None
    ref: Dict[str, str] = {"record_id": record_id}
    chain_id = value.get("chain_id")
    if isinstance(chain_id, str):
        ref["chain_id"] = chain_id
    return ref


class Artifact:
    """One bundle artifact.

    Ruling ``AD15-IR-5``: ``path`` -- the manifest-relative path -- is the TOTAL
    result identity and always exists, because the manifest lists every file.
    ``record_id`` is wire semantics and may be absent; an artifact that must be
    rejected at stage 0 may carry no usable one, and this evaluator MUST NOT
    synthesize it.
    """

    __slots__ = ("path", "value", "record_id", "chain_id", "artifact_type")

    def __init__(self, path: str, value: dict) -> None:
        self.path = path
        self.value = value
        record_id = value.get("record_id")
        # AD15-IR-18 step 5: an EMPTY string is still a string. The pre-erratum
        # `and record_id` guard here was a minLength rule this lane invented.
        self.record_id: Optional[str] = \
            record_id if isinstance(record_id, str) else None
        self.chain_id = value.get("chain_id")
        self.artifact_type = value.get("artifact_type")

    @property
    def ref(self) -> Optional[Dict[str, str]]:
        """The PRELIMINARY ``artifact_ref`` -- ``AD15-IR-18``'s projection over
        the parsed artifact value, known BEFORE invocation (contract 8.3.1).

        On the ``exit 0`` path it is REPLACED by the accepted verdict's closed
        ``artifact_ref`` (Source A); on every OTHER emitted entry this value IS
        the emitted one (Source B). Never a fabricated identity.
        """
        return artifact_ref_from_artifact(self.value)


def _bad_shape(detail: str) -> NonMeasurement:
    return NonMeasurement("bundle-shape-invalid", detail)


def build_artifacts(manifest: Manifest, parsed: Dict[str, Any]) -> List[Artifact]:
    """Bundle shape, pinned by contract 5, keyed on the scenario the manifest
    names -- not guessed from what the files happen to look like.
    """
    scenario_id = manifest.scenario_id
    entries = manifest.by_role("artifact")

    expected = 1 if scenario_id in SINGLE_ARTIFACT_FAMILY else 4
    if len(entries) != expected:
        raise _bad_shape(
            "%s requires exactly %d artifact(s); the bundle carries %d"
            % (scenario_id, expected, len(entries)))

    artifacts: List[Artifact] = []
    for entry in entries:
        value = parsed[entry.path]
        if not isinstance(value, dict):
            raise _bad_shape("artifact %r is not a JSON object" % entry.path)
        # AD15-IR-5: there is deliberately NO record_id precondition here. An
        # artifact with no usable record_id must reach the frozen stage-0
        # evaluation it belongs to rather than be converted into this
        # evaluator's own preflight failure.
        artifact_type = value.get("artifact_type")
        if artifact_type not in ARTIFACT_TYPES:
            # Ambiguity A7: kept because contract 5 pins FAMILY COMPOSITION,
            # which cannot be checked without artifact_type.
            raise _bad_shape(
                "artifact %r carries artifact_type %r, outside the four families"
                % (entry.path, artifact_type))
        # AD15-IR-18 REMOVES the non-string-`chain_id` preflight this lane
        # carried. `bundle-shape-invalid` is defined by 8.2.2 as artifact count,
        # family composition or operator-input composition, and a wrong-typed
        # `chain_id` is none of the three -- so the rule was this lane's own
        # invention. The projection now simply OMITS a non-string `chain_id`,
        # and the artifact reaches the frozen stage-0 evaluation that owns the
        # schema question. Removing it is also what makes W1-BLK-ARTIFACT-REF's
        # schema-invalid Source-B cells reachable at all.
        artifacts.append(Artifact(entry.path, value))

    if scenario_id in SINGLE_ARTIFACT_FAMILY:
        family = SINGLE_ARTIFACT_FAMILY[scenario_id]
        if artifacts[0].artifact_type != family:
            raise _bad_shape(
                "%s requires the single artifact of the %s family; the bundle "
                "carries a %s" % (scenario_id, family, artifacts[0].artifact_type))
    else:
        present = sorted(a.artifact_type for a in artifacts)
        if present != sorted(ARTIFACT_TYPES):
            raise _bad_shape(
                "%s requires exactly one each of Decision, Control, Execution and "
                "Effect; the bundle carries %s" % (scenario_id, ", ".join(present)))

    # AD15-IR-6 (E3-1) REMOVED the two record_id preconditions that stood here.
    # A multi-artifact bundle carrying an artifact with no usable record_id is
    # no longer failed closed: the envelope now orders on artifact_path, which
    # always exists, so the envelope -- and the request_envelope_digest harness
    # duty 2 compares -- is always defined, and the artifact reaches the frozen
    # stage-0 evaluation it belongs to. A duplicate record_id is likewise not a
    # preflight rule: contract 5 pins it as R-A's business ("more than one match
    # is ambiguous and fails closed"), which a preflight rejection would make
    # unreachable, and 8.2.2 confines `bundle-shape-invalid` to artifact count,
    # family composition and operator-input composition. See recorded A6.

    # AD15-IR-5 / contract 8.4: result ordering is UTF-8 byte order of
    # artifact_path, which always exists -- not of record_id, which may not.
    artifacts.sort(key=lambda a: byte_key(a.path))
    return artifacts


def check_operator_composition(manifest: Manifest) -> Dict[str, FileEntry]:
    """Official W1 composition: exactly one ``bindings``, exactly one
    ``revocation``, exactly one ``independence_policy``, and NO ``clock``.

    ``clock`` remains a legal ``role`` for future runs; it simply does not occur
    in this one, because no scenario here evaluates freshness.
    """
    clocks = manifest.by_role("clock")
    if clocks:
        raise _bad_shape(
            "official W1 bundles carry no clock input; the bundle carries %d"
            % len(clocks))
    selected: Dict[str, FileEntry] = {}
    for role in REQUIRED_OPERATOR_ROLES:
        found = manifest.by_role(role)
        if len(found) != 1:
            raise _bad_shape(
                "official W1 bundles carry exactly one %s input; the bundle "
                "carries %d" % (role, len(found)))
        selected[role] = found[0]
    return selected


# --------------------------------------------------------------------------
# Frozen-verifier digest assertion (contract 3, 8.2.1)
# --------------------------------------------------------------------------

def class_verification_dir() -> str:
    return os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), *CLASS_VERIFICATION_RELPATH))


def frozen_verifier_path() -> str:
    return os.path.join(class_verification_dir(), *FROZEN_VERIFIER_RELPATH)


def frozen_contract_path() -> str:
    return os.path.join(class_verification_dir(), *FROZEN_CONTRACT_RELPATH)


FROZEN_FILES = (
    ("class_verifier", frozen_verifier_path, FROZEN_VERIFIER_SHA256),
    ("class_verifier_contract", frozen_contract_path, FROZEN_CONTRACT_SHA256),
)


def read_frozen_file(path: str) -> bytes:
    """Read one frozen-identity file, raising ``OSError`` verbatim.

    A named seam, so the E5-4 boundary between a frozen identity that cannot be
    READ and one that does not MATCH can be exercised deterministically rather
    than only through filesystem permissions, which are not portable.
    """
    with open(path, "rb") as handle:
        return handle.read()


def measure_frozen_digests() -> Tuple[Optional[Dict[str, str]],
                                      Optional[Tuple[str, str]]]:
    """Recompute the two frozen files THIS lane uses (contract 8.2.1, E5-4).

    Returns ``(verifier_digests, problem)``:

    * ``verifier_digests`` is the EXACT TWO-entry object built from the values
      this lane recomputed -- never a carried constant, never one entry -- or
      ``None`` when either file could not be READ, in which case there is no
      digest to emit and none is invented;
    * ``problem`` is ``(reason, detail)`` or ``None``.

    THE TWO FAILURES ARE DIFFERENT THINGS AND CARRY DIFFERENT REASONS. A frozen
    file that cannot be read is ``frozen-identity-unreadable`` with
    ``verifier_digests: null``: the identity was never measured. A file that was
    read and disagrees with its pin is ``verifier-digest-mismatch``, and the
    ACTUAL recomputed two-entry object is retained -- a reader needs to see what
    was actually there, not what was expected. Unreadability is decided FIRST,
    over both files, because a two-entry object cannot be built at all when one
    of the two is missing from the measurement.
    """
    measured: Dict[str, str] = {}
    unreadable: Optional[str] = None
    for key, path_of, _expected in FROZEN_FILES:
        path = path_of()
        try:
            data = read_frozen_file(path)
        except OSError as exc:
            if unreadable is None:
                unreadable = ("frozen file %s could not be read, so its digest "
                              "cannot be recomputed: %s" % (path, exc))
            continue
        measured[key] = "sha256:" + sha256_hex(data)
    if unreadable is not None:
        # Contract 8.2.1 step 3: verifier_digests is null, and it is null ONLY
        # here. Emitting a partial object would be the fabrication the ruling
        # exists to forbid.
        return None, ("frozen-identity-unreadable", unreadable)
    for key, path_of, expected in FROZEN_FILES:
        if measured[key] != "sha256:" + expected:
            # Step 5: the actual two-entry object is RETAINED alongside the
            # mismatch; the expected value is named in `detail` only.
            return measured, ("verifier-digest-mismatch",
                              "%s: contract pins %s, the tree measures %s"
                              % (path_of(), expected, measured[key][7:]))
    return measured, None


def assert_frozen_identity(problem: Optional[Tuple[str, str]]) -> None:
    """Contract 3 and 8.2.1 step 3/5: an unreadable or mismatched frozen
    identity is a hard ERROR -- the run is not valid and no Level-1 verdict is
    emitted. Raised at the PINNED position: immediately after bundle identity
    and before any other post-identity preflight, so every other post-identity
    result carries a populated two-entry ``verifier_digests``.
    """
    if problem is not None:
        raise NonMeasurement(problem[0], problem[1])


# --------------------------------------------------------------------------
# Request envelope (contract 5.1)
# --------------------------------------------------------------------------

def build_envelope(primary: Artifact, artifacts: List[Artifact]) -> dict:
    """The closed section-0 envelope for ``primary``.

    ``related_artifacts`` is EVERY OTHER artifact of the same bundle and no
    others, ascending by UTF-8 byte order of the MANIFEST-RELATIVE
    ``artifact_path`` (ruling ``AD15-IR-6``); for a single-artifact scenario it
    is the EMPTY ARRAY -- present, never absent. ``head_witness`` is never
    added: contract 5 pins it absent from every official W1 bundle and the
    closed role set cannot express one.

    Ordering keys on ``artifact_path`` because it ALWAYS exists -- the manifest
    lists every file -- so the envelope, and with it the
    ``request_envelope_digest`` harness duty 2 compares, is always defined even
    when an artifact carries no usable ``record_id``. ``record_id`` remains only
    the AIREP semantic reference-resolution key (R-A); the manifest path never
    participates in that resolution. The path is the ORDERING key only: it is
    not a member of the envelope, which carries artifact values alone.
    """
    related = sorted((a for a in artifacts if a is not primary),
                     key=lambda a: byte_key(a.path))
    return {
        "artifact": primary.value,
        "related_artifacts": [a.value for a in related],
    }


def envelope_bytes(envelope: dict) -> bytes:
    """RFC 8785 canonical bytes; ``request_envelope_digest`` is over exactly these."""
    return jcs.canonicalize(envelope)


# --------------------------------------------------------------------------
# Frozen-verifier invocation (contract 3: subprocess, never imported)
# --------------------------------------------------------------------------

def _run_invalid(detail: str, entries: List[dict]) -> NonMeasurement:
    """Erratum 2: every abnormal frozen run, and only those, land here.

    The frozen process STARTED but the invocation did not produce one of the
    process/result shapes the frozen contract permits.
    """
    return NonMeasurement("verifier-run-invalid", detail, artifacts=entries)


def verdict_from_stdout(artifact: "Artifact",
                        stdout: bytes) -> Tuple[Optional[dict], Optional[str]]:
    """Decode the single verdict object an ``exit 0`` invocation owes us.

    Returns ``(verdict, problem)``. It DOES NOT RAISE: ruling ``AD15-IR-12``
    makes a ``verifier-run-invalid`` run contribute its ``artifacts[]`` entry
    before the scenario aborts, so the caller must be able to build that entry
    from a rejected result rather than being unwound past it. The pre-erratum
    construction raised from here and therefore emitted NO entry for a
    malformed ``exit 0`` -- which ``AD15-IR-12``'s three-outcome table now
    forbids.

    Erratum 2 enumerates the exit-0 failures, all `verifier-run-invalid`:
    empty stdout, stdout that is not parseable as STRICT JSON, and stdout
    carrying a malformed, multiple or wrong-shape result instead of the single
    expected verdict object. ``AD15-IR-18`` adds one more, enforced by the shape
    gate: a verdict whose ``artifact_ref`` is not closed.

    Strictness is the contract's own word. ``NaN`` / ``Infinity`` are rejected
    because JSON has no such literals; a second concatenated document is
    rejected because ``json.loads`` refuses trailing data.

    A REJECTED ``exit 0`` YIELDS ``verifier_result: null``. Contract 8.3 types
    that member as "the verdict verbatim WHEN ONE WAS EMITTED", and a result the
    shape gate refused is not a verdict; ``AD15-IR-18``'s Source B places
    "exit 0 whose output the result-shape gate rejects" on the PRELIMINARY
    projection path, which is only coherent if no accepted verdict exists to
    copy from. Putting the rejected object in a field typed as the verdict would
    also smuggle unvalidated frozen output into a Class-1 comparison field.
    """
    if not stdout.strip():
        return None, ("frozen verifier exited 0 for %s with empty stdout"
                      % artifact.path)
    try:
        decoded = json.loads(stdout.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        return None, ("frozen verifier exited 0 for %s but stdout is not "
                      "parseable as strict JSON: %s" % (artifact.path, exc))
    if not isinstance(decoded, dict):
        return None, ("frozen verifier exited 0 for %s but stdout carries a %s, "
                      "not the single expected verdict object"
                      % (artifact.path, type(decoded).__name__))
    wrong = _wrong_shape(decoded)
    if wrong is not None:
        return None, ("frozen verifier exited 0 for %s but the result is not a "
                      "normalized verdict envelope: %s" % (artifact.path, wrong))
    return decoded, None


#: The normalized verdict envelope, pinned by the FROZEN
#: ``CLASS_VERIFIER_CONTRACT.md`` section 2 -- required members, the closed
#: ``class`` set, the five always-present reason arrays, and the closed
#: ``observer_assessment`` set. This is a shape check on what the frozen
#: verifier returned, NOT a re-implementation of any frozen decision: no value
#: here is recomputed, compared with the artifact, or allowed to influence a
#: predicate. Section 2 does not declare the envelope closed, so an unknown
#: member is deliberately NOT rejected.
VERDICT_CHANNELS = (
    "authenticated_failures", "authenticated_withheld", "authenticated_caveats",
    "witnessed_failures", "witnessed_withheld",
)
VERDICT_CLASSES = frozenset({
    "AIREP-Core", "AIREP-Authenticated", "AIREP-Witnessed"})
VERDICT_OBSERVER_ASSESSMENTS = frozenset({
    "same_executor", "independent", "unknown", "not_applicable"})


def _wrong_shape(verdict: dict) -> Optional[str]:
    """Return why ``verdict`` is not a normalized verdict envelope, or ``None``.

    Without this, an ``exit 0`` carrying an arbitrary JSON object reaches the
    Level-1 mapping, where every reader degrades to its positive branch --
    ``verdict.get("authenticated_failures") or []`` sees no failure,
    ``verdict.get("authenticated_withheld") or []`` sees no withheld tier, and
    R-C sees no ``unknown``. The result is a `MEASURED` / `ACCEPT` built on a
    measurement that never happened, which is the exact laundering contract 7.1
    forbids. E2-2 names this case, so it is refused here.
    """
    for member in ("artifact_ref", "class", "observer_assessment", "evidence"):
        if member not in verdict:
            return "required member %r is absent" % member
    if not isinstance(verdict["artifact_ref"], dict):
        return "artifact_ref is not an object"
    # Ruling AD15-IR-18: THE GATE MUST REJECT a verdict whose `artifact_ref`
    # carries any member other than `record_id` and `chain_id`, as
    # `verifier-run-invalid`. This is a gate THIS contract adds, not a
    # re-reading of the frozen one -- the frozen contract enumerates
    # `artifact_ref` without declaring that nested object closed, so without
    # this obligation one evaluator could accept an extra member and COPY it
    # while another rejected the verdict. `artifact_ref` is a Class-1 cross-lane
    # equality field and an open nested object cannot be one. Enforcing closure
    # HERE is what makes the exit-0 copy verbatim over a value already known to
    # be closed.
    stray = sorted(set(verdict["artifact_ref"]) - ARTIFACT_REF_MEMBERS)
    if stray:
        return ("artifact_ref carries member(s) outside the closed set "
                "{record_id, chain_id}: %s" % ", ".join(stray))
    if not isinstance(verdict["evidence"], dict):
        return "evidence is not an object"
    if verdict["class"] not in VERDICT_CLASSES:
        return "class %r is outside the closed set" % (verdict["class"],)
    if verdict["observer_assessment"] not in VERDICT_OBSERVER_ASSESSMENTS:
        return ("observer_assessment %r is outside the closed set"
                % (verdict["observer_assessment"],))
    for channel in VERDICT_CHANNELS:
        if channel not in verdict:
            return "reason array %r is absent; frozen 2 requires all five always" % channel
        if not isinstance(verdict[channel], list):
            return "reason array %r is not an array" % channel
        # Frozen contract 2 and 5: these are SORTED SETS OF REASONS drawn from a
        # closed, ASCII-by-construction registry. A non-string element is not a
        # reason, so the envelope is wrong-shape -- E2-2's case, and
        # `verifier-run-invalid`.
        #
        # This is load-bearing, not tidiness. Contract 7.1 turns on whether a
        # channel is NON-EMPTY, and `withheld_reasons_from_entries` reports only
        # string reasons verbatim; without this gate a channel whose elements
        # were objects passed the shape check, contributed no reported entry,
        # and the scenario came out MEASURED / ACCEPT -- laundering the ABSENCE
        # OF A MEASUREMENT into a positive Level-1 result, which is exactly what
        # 7.1 exists to forbid.
        for element in verdict[channel]:
            if not isinstance(element, str):
                return ("reason array %r carries a %s; frozen 2 makes it a "
                        "sorted set of registry reason strings"
                        % (channel, type(element).__name__))
    return None


def invoke_frozen_verifier(request: bytes,
                           flags: List[str]) -> Tuple[Optional[int], bytes, bytes]:
    """Run the frozen Python class verifier on one request envelope.

    Returns ``(exit_code, stdout, stderr)``. Ruling ``AD15-IR-15``: a frozen
    verifier killed by a signal plainly STARTED, so it is
    ``verifier-run-invalid`` and contributes an entry -- but there is NO
    PORTABLE INTEGER to put in ``verifier_exit_code``. Language runtimes
    disagree: one conventionally reports signal death as a negative return code,
    another reports no status at all plus a separate signal name. An entry
    demanding an integer "verbatim" would force one lane to fabricate a value.

    So ``exit_code`` is ``None`` exactly when the process DID NOT EXIT NORMALLY.
    CPython encodes POSIX signal death as a NEGATIVE ``returncode``; that
    encoding is a runtime convention, not a contract value, so it is translated
    here and NEVER emitted. The signal is useful to a human, so it reaches
    ``nonmeasurement.detail`` -- which contract 8.7 places in Class 4,
    diagnostic-only -- and NO NORMATIVE FIELD.

    Nothing is written into the frozen tree: the request lives in a temporary
    directory that is removed on return.
    """
    verifier = frozen_verifier_path()
    with tempfile.TemporaryDirectory(prefix="airep-interop-eval-") as workdir:
        request_path = os.path.join(workdir, "request.json")
        with open(request_path, "wb") as handle:
            handle.write(request)
        argv = [sys.executable, verifier, "--request", request_path] + list(flags)
        try:
            completed = subprocess.run(argv, capture_output=True, check=False)
        except OSError as exc:
            raise NonMeasurement(
                "verifier-not-invocable", "frozen verifier could not be executed: %s" % exc)
    code: Optional[int] = completed.returncode
    if isinstance(code, int) and code < 0:
        code = None                       # abnormal termination (AD15-IR-15)
    return code, completed.stdout, completed.stderr


# --------------------------------------------------------------------------
# Reconciliation predicates (contract 6)
# --------------------------------------------------------------------------

def resolve_reference(reference: Any, artifacts: List[Artifact]) -> str:
    """v0.2 reference semantics: match ``record_id``, additionally ``chain_id``
    when the reference carries one. Zero matches is unresolved; more than one is
    ambiguous and fails closed. An evaluator MUST NOT pick one (contract 5).
    """
    if not isinstance(reference, dict):
        return "unresolved"
    record_id = reference.get("record_id")
    if not isinstance(record_id, str):
        return "unresolved"
    chain_id = reference.get("chain_id")
    matches = [
        a for a in artifacts
        if a.record_id == record_id and (chain_id is None or a.chain_id == chain_id)
    ]
    if len(matches) == 1:
        return "resolved"
    return "ambiguous" if len(matches) > 1 else "unresolved"


#: The complete cross-artifact reference set contract 6 R-A names:
#: Control->Decision, Execution->Decision, Effect->Decision, Effect->Execution.
REFERENCE_EDGES = {
    "control": ("decision_ref",),
    "execution": ("decision_ref",),
    "effect": ("decision_ref", "execution_ref"),
}


def predicate_r_a(artifacts: List[Artifact]) -> Tuple[str, List[str]]:
    """R-A -- every cross-artifact reference in the bundle resolves uniquely.

    Unique reference resolution AND NOTHING MORE (contract 6, confirmed at
    erratum): there is deliberately no check that a ``decision_ref`` resolves to
    an artifact of the Decision family. Adding one would be a stricter, unpinned
    predicate; bundle shape already fixes family composition.
    """
    problems: List[str] = []
    for artifact in artifacts:
        for member in REFERENCE_EDGES.get(artifact.artifact_type or "", ()):
            outcome = resolve_reference(artifact.value.get(member), artifacts)
            if outcome != "resolved":
                problems.append("%s /%s %s" % (artifact.path, member, outcome))
    return (FAIL if problems else PASS), problems


def predicate_r_b(artifacts: List[Artifact]) -> Tuple[str, List[str]]:
    """R-B -- the Control's ``authorized_action_digest`` and the Execution's
    ``executed_action_digest``, compared as EXACT STRINGS. Both are
    ``sha256_digest`` by schema, so no normalization, case folding or re-hashing
    is performed.
    """
    control = _sole(artifacts, "control")
    execution = _sole(artifacts, "execution")
    authorized = control.value.get("authorized_action_digest")
    executed = execution.value.get("executed_action_digest")
    if isinstance(authorized, str) and isinstance(executed, str) \
            and authorized == executed:
        return PASS, []
    return FAIL, ["authorized %r != executed %r" % (authorized, executed)]


def predicate_r_c(artifacts: List[Artifact],
                  verdicts: Dict[str, Optional[dict]]) -> Tuple[str, List[str]]:
    """R-C -- independence, TAKEN FROM the frozen verifier's
    ``observer_assessment`` for the Effect and never re-derived here: that is a
    frozen stage-8 property, and re-implementing it would create a second,
    unpinned definition (contract 6).
    """
    effect = _sole(artifacts, "effect")
    # Keyed by artifact_path: AD15-IR-5 makes it the total result identity, and
    # it is the only key guaranteed to exist and to be unique.
    verdict = verdicts.get(effect.path)
    if not isinstance(verdict, dict):
        raise NonMeasurement(
            "internal-error",
            "R-C has no frozen verdict for the Effect %r" % effect.path)
    wire = effect.value.get("observer_relationship")
    effective = verdict.get("observer_assessment")
    if wire == "independent" and effective == "unknown":
        return FAIL, ["wire observer_relationship 'independent', effective 'unknown'"]
    return PASS, []


def _sole(artifacts: List[Artifact], artifact_type: str) -> Artifact:
    found = [a for a in artifacts if a.artifact_type == artifact_type]
    if len(found) != 1:
        # Unreachable: bundle shape already pinned exactly one of each.
        raise NonMeasurement(
            "internal-error",
            "expected exactly one %s after shape validation, found %d"
            % (artifact_type, len(found)))
    return found[0]


# --------------------------------------------------------------------------
# Level-1 mapping (contract 7)
# --------------------------------------------------------------------------

def map_level1(reject: bool, predicates: Dict[str, str]) -> str:
    """Contract 7, in the pinned order."""
    if reject:
        return REJECT
    if predicates["R_C"] == FAIL:
        return INDEPENDENCE_NOT_ESTABLISHED
    if predicates["R_A"] == FAIL or predicates["R_B"] == FAIL:
        return RECONCILIATION_MISMATCH
    return ACCEPT


# --------------------------------------------------------------------------
# Result object (contract 8.2)
# --------------------------------------------------------------------------

def build_result(scenario_id: str, status: str, level1: Optional[str],
                 predicates: Optional[Dict[str, str]],
                 nonmeasurement: Optional[dict], artifacts: List[dict],
                 withheld_reasons: List[dict],
                 verifier_digests: Optional[Dict[str, str]]) -> dict:
    return {
        "scenario_id": scenario_id,
        "measurement_status": status,
        "level1": level1,
        "predicates": predicates,
        "nonmeasurement": nonmeasurement,
        "artifacts": artifacts,
        "withheld_reasons": withheld_reasons,
        "verifier_digests": verifier_digests,
        "evaluator_version": EVALUATOR_VERSION,
    }


def nonmeasurement_object(exc: NonMeasurement) -> dict:
    """The closed contract-8.2.2 object. ``json_pointer`` appears only for
    ``numeric-preflight-violation``, where it is mandatory.
    """
    obj = {"reason": exc.reason, "detail": exc.detail}
    if exc.json_pointer is not None:
        obj["json_pointer"] = exc.json_pointer
    return obj


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def evaluate_bundle(args, invoke=None) -> dict:
    """Evaluate exactly one bundle and return the MEASURED result object.

    Raises ``BundleIdentityError`` (exit 1), ``UsageError`` (exit 2) or
    ``NonMeasurement`` (exit 3). ``invoke`` is the frozen-verifier subprocess
    seam, resolved from the module global when not supplied so that tests can
    substitute a stub and exercise the mapping without any corpus bytes.
    """
    if invoke is None:
        invoke = invoke_frozen_verifier
    bundle_dir = os.path.abspath(args.bundle)
    # exit-1 band ends here
    doc, scenario_id, duplicates = load_manifest_identity(bundle_dir)
    # Contract 8.2.1 step 2 (E5-4): IMMEDIATELY after identity, and BEFORE any
    # other post-identity preflight, this lane reads its own frozen identity
    # pair and recomputes SHA-256 over each. Ruling AD15-IR-8 (E5-1) makes the
    # identity above monotonic, so everything from here on owes a result object
    # naming the scenario -- including an unreadable frozen file, which is why
    # it needs a reason of its own rather than the exit-1 band.
    verifier_digests, frozen_problem = measure_frozen_digests()
    # Contract 8.3.1 rule 3: once invocation begins, `artifacts[]` carries an
    # entry for each invocation ACTUALLY ATTEMPTED. The list is owned here so
    # that a fault raised anywhere downstream -- including the generic net
    # below, which is outside `_evaluate`'s frame -- still reports what was
    # attempted, rather than the `artifacts: []` that asserts a pre-invocation
    # failure which did not happen.
    entries: List[dict] = []
    try:
        # Step 3/5 before step 6: no bundle traversal and no remaining preflight
        # begins until the frozen identity has been read and asserted.
        assert_frozen_identity(frozen_problem)
        return _evaluate(args, bundle_dir, doc, scenario_id, duplicates, invoke,
                         verifier_digests, entries)
    except NonMeasurement as exc:
        # Identity IS established from here on, so the caller owes a result
        # object naming the scenario it failed on (contract 8.5).
        exc.scenario_id = scenario_id
        exc.verifier_digests = verifier_digests
        if not exc.artifacts:
            exc.artifacts = list(entries)
        # Contract 8.2: `withheld_reasons` is emitted UNCONDITIONALLY, `[]` when
        # nothing is withheld. It is derived here from whatever entries the run
        # actually produced, so an aborted scenario reports the channels it
        # OBSERVED rather than asserting an absence it never measured. On a
        # pre-invocation failure there are no entries and the array is `[]`,
        # which is then a measured emptiness rather than a default.
        exc.withheld_reasons = withheld_reasons_from_entries(exc.artifacts)
        raise
    except (UsageError, BundleIdentityError):
        raise
    except Exception as exc:                # noqa: BLE001 -- deliberate net
        # Contract 8.2.2: `internal-error` exists so that an unexpected fault
        # AFTER identity is established still produces a result object naming
        # the scenario, rather than a crash the harness has to infer. Erratum 2
        # narrows it to exactly this -- the evaluator's OWN fault.
        wrapped = NonMeasurement(
            "internal-error",
            "unexpected %s in the evaluator: %s" % (type(exc).__name__, exc))
        wrapped.scenario_id = scenario_id
        wrapped.verifier_digests = verifier_digests
        wrapped.artifacts = list(entries)
        wrapped.withheld_reasons = withheld_reasons_from_entries(wrapped.artifacts)
        raise wrapped from exc


def _evaluate(args, bundle_dir: str, doc: dict, scenario_id: str,
              duplicates: Sequence[str], invoke,
              verifier_digests: Optional[Dict[str, str]],
              entries: List[dict]) -> dict:
    """Ruling ``AD15-IR-13`` -- the canonical evaluation pipeline, stages 4-13.

    Stages 1-3 have already run in ``main`` and ``evaluate_bundle``: CLI and
    meta-action handling, the direct-read bundle identity, and the
    frozen-verifier identity read-then-match. From here each stage RUNS TO
    COMPLETION over the whole bundle before the next begins, and the first stage
    that produces a failure determines the reported reason. No later stage
    overrides an earlier stage's failure, and nothing is interleaved for
    efficiency in a way that would change which failure is reported.

    THE BARRIERS ARE THE WHOLE POINT. The pre-erratum construction validated
    each listed path end-to-end in manifest order, so a bundle with one
    unreadable file and a DIFFERENT file's digest mismatch reported whichever
    came first -- and that reading satisfied the old "complete the whole bundle
    preflight first" just as well as this one does. Stages 5, 6 and 7 are now
    separate barriers, so the same bundle reports ``bundle-file-missing``, then
    ``bundle-file-unreadable``, then ``manifest-digest-mismatch``, in that
    order, whatever the manifest order happens to be.
    """
    #  4  manifest structure and closure --------------------------------------
    manifest = validate_manifest(doc, scenario_id, duplicates)
    #  5  canonical traversal: entry kind, layout closure, listed-file presence
    stage_traversal(bundle_dir, manifest)
    #  6  ALL listed-file reads ----------------------------------------------
    contents = stage_reads(bundle_dir, manifest)
    #  7  ALL digest checks ---------------------------------------------------
    stage_digests(manifest, contents)
    #  8  JSON bytes, parsing, the two canonicalization rules -----------------
    parsed = stage_json(manifest, contents)
    #  9  bundle and operator-input shape; operator assertions ----------------
    #     Mechanism precedence within the stage: `bundle-shape-invalid` is
    #     listed before `operator-input-assertion-mismatch`, so the bundle's own
    #     composition is settled before any assertion an operator makes ABOUT
    #     it. The worked case: a manifest with two `independence_policy` files
    #     AND a `--bindings` flag pointing at the revocation file reports
    #     `bundle-shape-invalid`.
    artifacts = build_artifacts(manifest, parsed)
    operator_entries = check_operator_composition(manifest)
    _assert_operator_flags_consistent(args, bundle_dir, operator_entries)
    # 10  numeric preflight ---------------------------------------------------
    stage_numeric(manifest, parsed)

    flags: List[str] = []
    for role in REQUIRED_OPERATOR_ROLES:
        entry = operator_entries[role]
        flags += [OPERATOR_FLAG[role],
                  os.path.join(bundle_dir, *entry.path.split("/"))]

    # 11  artifact invocation, in AD15-IR-12 order and subject to its abort ---
    verdicts = stage_invoke(scenario_id, artifacts, flags, invoke, entries)

    # 12  contract 7.1, AFTER stage 11 completes (AD15-IR-10) -----------------
    withheld_reasons = withheld_reasons_from_entries(entries)
    # Contract 7.1 turns on "ANY EMITTED FROZEN-VERIFIER VERDICT carrying a
    # NON-EMPTY `authenticated_withheld` channel". The condition is therefore
    # read from the VERDICT ITSELF, not from the reported `withheld_reasons`
    # array -- which is a PROJECTION of it, and a projection can only ever be
    # smaller. Testing the projection made the rule silently conditional on the
    # projection being faithful.
    if any_authenticated_withheld(entries):
        # Contract 7.1: withheld is the ABSENCE of a measurement. Not REJECT --
        # nothing was refused -- and emphatically not ACCEPT.
        #
        # THE RULE IS SCENARIO-INDEPENDENT (E5-5). `scenario_id` appears in the
        # detail string and NOWHERE in the condition: ANY emitted verdict with a
        # non-empty `authenticated_withheld` channel invalidates the scenario,
        # regardless of which of the twelve it is. An instrument that consults
        # an expected-outcome oracle is not measuring. No expected-tier table
        # exists in this file, and none may be added.
        raise NonMeasurement(
            "authenticated-withheld",
            "a non-empty authenticated_withheld channel makes %s "
            "measurement-invalid (contract 7.1)" % scenario_id,
            withheld_reasons=withheld_reasons,
            artifacts=entries)

    # 13  predicates and the Level-1 verdict ----------------------------------
    if scenario_id in SINGLE_ARTIFACT_FAMILY:
        # A single-artifact scenario has no bundle graph, no Control/Execution
        # pair and no observer relationship: it is not run through the
        # predicates at all. NOT_APPLICABLE is a MEASURED outcome (8.2.3).
        predicates = {"R_A": NOT_APPLICABLE, "R_B": NOT_APPLICABLE,
                      "R_C": NOT_APPLICABLE}
    else:
        r_a, why_a = predicate_r_a(artifacts)
        r_b, why_b = predicate_r_b(artifacts)
        r_c, why_c = predicate_r_c(artifacts, verdicts)
        # All three are evaluated even when one has already failed: WHICH
        # predicate fired is the measurement (contract 6.1).
        predicates = {"R_A": r_a, "R_B": r_b, "R_C": r_c}
        for label, reasons in (("R-A", why_a), ("R-B", why_b), ("R-C", why_c)):
            for reason in reasons:
                warn("%s %s: %s" % (scenario_id, label, reason))

    reject = False
    for entry in entries:
        if entry["verifier_exit_code"] == 1:
            reject = True                  # invalid: no class at all
            continue
        verdict = entry["verifier_result"]
        if isinstance(verdict, dict) and (verdict.get("authenticated_failures") or []):
            reject = True                  # definitive Authenticated-tier failure

    level1 = map_level1(reject, predicates)

    # Contract 8.3.1 rule 4: a MEASURED result's artifacts[] length MUST equal
    # the bundle's artifact count from section 5.
    if len(entries) != len(artifacts):
        raise NonMeasurement(
            "internal-error",
            "MEASURED result would carry %d artifact entries for a %d-artifact "
            "bundle" % (len(entries), len(artifacts)),
            artifacts=entries)

    return build_result(scenario_id, MEASURED, level1, predicates, None, entries,
                        withheld_reasons, verifier_digests)


def stage_numeric(manifest: Manifest, parsed: Dict[str, Any]) -> None:
    """STAGE 10 -- the contract-5.1 numeric preflight, over every listed file.

    The comparison key gains its CONDITIONAL FOURTH COMPONENT here, and only
    here: ``numeric-preflight-violation`` is the one reason 8.2.2 permits a
    ``json_pointer`` on, so it is the one reason whose intra-file selection is
    OBSERVABLE. Two numbers in the same artifact both outside the envelope share
    a stage, a reason and a path; ascending UTF-8 byte order of the pointer
    string decides between them.

    THE POINTER IS RFC 6901 AGAINST THE INDIVIDUAL FILE the violation occurs in
    -- the artifact or operator-input document as parsed -- NEVER the request
    envelope. The check happens before any envelope exists, so an
    envelope-relative pointer would name a document that has not been built; and
    the two bases give different strings for the same violation
    (``/profiles/x`` against the artifact versus ``/artifact/profiles/x``
    against the envelope), which is a normative divergence under 8.7. This
    closes recorded ambiguity A2 in the direction ``E7-19`` pins.
    """
    best: Optional[Tuple[bytes, bytes, NonMeasurement]] = None
    for entry in manifest.entries:
        for pointer, why in numeric_preflight_all(parsed[entry.path]):
            candidate = (byte_key(entry.path), byte_key(pointer), NonMeasurement(
                "numeric-preflight-violation",
                "%s (%s): %s" % (entry.path, entry.role, why),
                json_pointer=pointer))
            if best is None or candidate[:2] < best[:2]:
                best = candidate
    if best is not None:
        raise best[2]


def stage_invoke(scenario_id: str, artifacts: List["Artifact"], flags: List[str],
                 invoke, entries: List[dict]) -> Dict[str, Optional[dict]]:
    """STAGE 11 -- ruling ``AD15-IR-12``: canonical invocation ORDER and
    FATAL-RUN FAIL-FAST.

    ``AD15-IR-11`` pinned what a spawn failure contributes to ``artifacts[]``,
    but not the two things that make the contribution observable. Adversarial
    review found that a four-artifact bundle failing at its SECOND artifact
    admitted ``[A]``, ``[C, D]`` and ``[A, C, D]`` -- all three conforming.

        ORDER. Artifact invocations proceed in ASCENDING UTF-8 BYTE ORDER of
        ``artifact_path`` -- the same key ``AD15-IR-5`` and ``AD15-IR-6``
        already use for identity and envelope ordering.

        FAIL-FAST ON A FATAL RUN.
          * ``verifier-not-invocable`` -- the current artifact contributes NO
            entry, entries for invocations that already completed are RETAINED,
            and the scenario ABORTS IMMEDIATELY;
          * ``verifier-run-invalid`` -- a concrete process result exists, so the
            current artifact DOES contribute its entry, and the scenario ABORTS
            IMMEDIATELY;
          * a clean ``exit 0`` verdict NEVER aborts, EVEN when it carries a
            non-empty ``authenticated_withheld`` channel: under ``AD15-IR-10``
            the remaining artifacts must still be evaluated for run validity
            before 7.1 is applied at all.

    The worked case is now single-valued: a bundle ``[A, B, C, D]`` whose B
    cannot be spawned yields ``artifacts[] = [A]``.

    TWO BEHAVIOURAL CORRECTIONS TO THIS LANE. The pre-erratum construction
    invoked EVERY artifact and only then swept the exit codes, so a bundle whose
    first artifact exited 2 yielded four entries rather than one; and a
    malformed ``exit 0`` raised out of the decoder before its entry was
    appended, yielding NO entry for a process that had plainly produced a
    concrete result.

    Stage 11 is also contract 8.6's one carve-out from the tie-break: invocation
    is SEQUENTIAL and stops at the first fatal run, so the reported reason is
    whichever fatal run is reached first and no comparison between reasons
    arises.
    """
    # AD15-IR-12 order. `build_artifacts` already sorts on this key; sorting
    # here too makes the invocation order a property of THIS function rather
    # than an inherited side effect of another one.
    ordered = sorted(artifacts, key=lambda a: byte_key(a.path))
    verdicts: Dict[str, Optional[dict]] = {}
    for artifact in ordered:
        request = envelope_bytes(build_envelope(artifact, artifacts))
        # Contract 8.3.1: `artifact_path` and a PRELIMINARY `artifact_ref` are
        # known before invocation; `request_envelope_digest` is a product of
        # successful envelope construction; only the last three fields are
        # products of a process attempt.
        preliminary_ref = artifact.ref
        try:
            code, stdout, stderr = invoke(request, flags)
        except NonMeasurement as exc:
            # AD15-IR-11 / AD15-IR-12: the process never started, so the current
            # artifact contributes NO entry -- an absent measurement is
            # represented by absence, never by a fabricated exit code or digest
            # -- earlier entries are retained, and the scenario aborts here.
            exc.artifacts = entries
            raise

        problem: Optional[str] = None
        verdict: Optional[dict] = None
        if code is None:
            # AD15-IR-15, middle row: the process STARTED and did not exit
            # normally. A FULL entry -- `artifact_path`, `artifact_ref`,
            # `request_envelope_digest` and a stderr digest over what the child
            # actually wrote -- in which exactly two measurements are missing.
            # This is emphatically NOT the AD15-IR-11 shape: abnormal
            # termination is the absence of an EXIT CODE, not of a process
            # ATTEMPT, and treating the two as one shape would discard the
            # evidence of a run that genuinely happened.
            problem = ("frozen verifier for %s did not exit normally; it "
                       "started, so no exit code exists to record"
                       % artifact.path)
        elif code == 0:
            verdict, problem = verdict_from_stdout(artifact, stdout)
        elif code == 1:
            # Contract 7.2: `exit 1` means run-invalid, NO VERDICT WAS EMITTED.
            # It reads as a Level-1 REJECT only when the request was
            # preflight-clean -- which reaching stage 11 establishes -- AND the
            # scenario's targeted predicate is stage-0 or stage-1 invalidity.
            # Cross-lane envelope equality is NOT part of that condition and
            # never was implementable here (AD15-IR-4, 8.1 duty 2).
            if scenario_id not in EXIT1_REJECT_SCENARIOS:
                problem = ("frozen verifier exit 1 for %s under %s is outside "
                           "the two contract-7.2 conditions, so it does not "
                           "qualify as a Level-1 REJECT"
                           % (artifact.path, scenario_id))
        else:
            # E2-2: exit 2, or any other exit the frozen contract does not
            # permit for this invocation. It is NOT `internal-error`, which is
            # now this evaluator's OWN unexpected fault only.
            problem = ("frozen verifier exited %d for %s; the frozen contract "
                       "permits no such exit for this invocation"
                       % (code, artifact.path))

        # AD15-IR-18 source selection. Source A is the ACCEPTED exit-0 verdict,
        # whose closed `artifact_ref` is copied VERBATIM. Source B is every
        # OTHER emitted entry -- defined by EXCLUSION, not by a list of outcomes
        # -- and carries the preliminary projection: a qualifying exit-1, a
        # NON-qualifying exit-1, exit 2, a rejected exit-0 shape, and abnormal
        # termination, which can occur BEFORE the frozen verifier reaches stage
        # 0 and therefore carries any artifact at all.
        emitted_ref = verdict["artifact_ref"] if verdict is not None \
            else preliminary_ref
        entries.append({
            "artifact_path": artifact.path,
            "artifact_ref": emitted_ref,
            "request_envelope_digest": digest_str(request),
            # AD15-IR-15: `null` when the process was terminated abnormally, the
            # integer verbatim when it exited normally. No signal name, signal
            # number or synthesized exit code enters any normative field.
            "verifier_exit_code": code,
            "verifier_result": verdict,
            # Hashed for audit and NEVER parsed for semantics (contract 8.3).
            "verifier_stderr_digest": digest_str(stderr),
        })
        verdicts[artifact.path] = verdict
        if problem is not None:
            raise _run_invalid(problem, entries)
    return verdicts


def any_authenticated_withheld(entries: Sequence[dict]) -> bool:
    """Contract 7.1's condition, read from the frozen verdicts themselves.

    Deliberately independent of ``withheld_reasons_from_entries``: that function
    REPORTS, this one DECIDES, and a reporting projection must never be able to
    narrow a normative condition. The two are kept apart so that no future
    change to the reported shape can quietly change what is measured.
    """
    for entry in entries:
        verdict = entry.get("verifier_result")
        if isinstance(verdict, dict) and (verdict.get("authenticated_withheld") or []):
            return True
    return False


def withheld_reasons_from_entries(entries: Sequence[dict]) -> List[dict]:
    """Ruling ``AD15-IR-16`` -- ``withheld_reasons`` has a PINNED ENTRY SHAPE.

    This lane recorded the per-entry shape as unpinned (A5) and chose one for
    itself: a per-ARTIFACT object carrying ``artifact_path``, ``artifact_ref``
    and the two channel arrays. That was tolerable while the member sat outside
    the parity surface. Contract 8.7 now makes ``withheld_reasons`` Class-1
    cross-lane equality data, so an unpinned entry shape is two lanes emitting
    different objects for the same withheld channel and calling it conformance.

    The shape is now one entry PER (artifact, channel, reason)::

        artifact_path  the artifact the channel came from -- the same identity
                       key AD15-IR-5 pins
        channel        the frozen channel name, VERBATIM: `authenticated_withheld`
                       or `witnessed_withheld`
        reason         the withheld reason string, VERBATIM from the frozen
                       verdict, never re-worded

    ordered by ``(artifact_path, channel, reason)`` in UTF-8 byte order and
    carrying NO OTHER MEMBER. Verbatim matters for the same reason it matters in
    ``verifier_result``: a withheld reason is the frozen verifier's OUTPUT, and
    an evaluator that paraphrases it has substituted its own text for a
    measurement.

    Non-string channel members are skipped rather than stringified -- step 6 of
    ``AD15-IR-18``'s no-coercion principle, applied here. The frozen shape gate
    has already established that each channel is an array; a non-string element
    inside one is frozen output this evaluator has no licence to rewrite.

    It is computed from whatever entries exist, in EVERY result -- `MEASURED`,
    `MEASUREMENT_INVALID` and `ERROR` alike -- so that an aborted run reports
    the channels it actually observed rather than asserting, with `[]`, an
    absence it never measured.
    """
    out: List[dict] = []
    for entry in entries:
        verdict = entry.get("verifier_result")
        if not isinstance(verdict, dict):
            continue
        for channel in ("authenticated_withheld", "witnessed_withheld"):
            for reason in (verdict.get(channel) or []):
                if not isinstance(reason, str):
                    continue
                out.append({
                    "artifact_path": entry["artifact_path"],
                    "channel": channel,
                    "reason": reason,
                })
    out.sort(key=lambda r: (byte_key(r["artifact_path"]), byte_key(r["channel"]),
                            byte_key(r["reason"])))
    return out


def _assert_operator_flags_consistent(args, bundle_dir: str,
                                      selected: Dict[str, FileEntry]) -> None:
    """Ruling ``AD15-IR-14`` -- a post-identity operator assertion mismatch is
    RESULT-BEARING. This CLOSES recorded ambiguity A1's exit-band note.

    Contract 8.1 shows ``interop-eval --bundle DIR [operator-input flags]``,
    while contract 5 pins the operator inputs as bundle members addressed by the
    closed ``role`` set and 5.1 says the evaluator "passes through the files the
    bundle ships". Role-derivation is the determinate reading and is what this
    evaluator uses; the three flags are accepted ONLY as a consistency
    assertion, so a flag can never change what is measured.

    What was OPEN was the exit band. This lane raised a ``UsageError`` -- exit
    2, empty stdout -- while recording that the mismatch is only DETECTABLE
    after ``manifest.json`` has yielded a usable ``scenario_id``, which
    contradicts the rule that an established identity is owed a result object.
    The ruling settles it:

        A CLI SYNTAX ERROR -- unknown option, missing value, malformed argument
        -- remains exit 2 with empty stdout, because it is detectable before
        anything is read.

        A SEMANTIC OR PATH MISMATCH between a supplied operator-input flag and
        the manifest, being detectable only after identity is established, is
        reason ``operator-input-assertion-mismatch``, ``ERROR``, EXIT 3, with a
        result object naming the scenario.

    The mandatory twelve are unaffected -- the official harness passes no
    operator-input flags, so this reason is unreachable in an official run. It
    is pinned anyway, because "unreachable in the official run" is precisely the
    class of gap that produced the ``--help`` divergence in Erratum 4 and the
    entry-kind divergence in Erratum 6.
    """
    supplied = (("bindings", args.bindings),
                ("independence_policy", args.independence_policy),
                ("revocation", args.revocation))
    for role, value in supplied:
        if value is None:
            continue
        expected = os.path.realpath(
            os.path.join(bundle_dir, *selected[role].path.split("/")))
        given = os.path.realpath(
            value if os.path.isabs(value) else os.path.join(os.getcwd(), value))
        if given != expected:
            raise NonMeasurement(
                "operator-input-assertion-mismatch",
                "%s names %s, but the bundle manifest selects %s for role %r; "
                "operator inputs are the bundle's own (contract 5.1)"
                % (OPERATOR_FLAG[role], given, expected, role))


# --------------------------------------------------------------------------
# Contract 8.7 -- result-shape closure and the cross-lane normative projection
# --------------------------------------------------------------------------

def validate_result_shape(result: Any) -> Optional[str]:
    """Return why ``result`` is not a conforming result object, or ``None``.

    Contract 8.7: "A result object carrying an UNKNOWN MEMBER AT ANY CLOSED
    LEVEL is INVALID -- it is not silently dropped from the projection.
    Excluding it would let a lane smuggle an uncompared field into a result that
    still passed the projection; the closed member set exists to prevent exactly
    that."

    This is a gate over THIS lane's own output. It is not a cross-lane
    comparison and needs no peer material.
    """
    if not isinstance(result, dict):
        return "result is not a JSON object"
    stray = sorted(set(result) - RESULT_MEMBERS)
    if stray:
        return "result carries unknown member(s): %s" % ", ".join(stray)
    missing = sorted(RESULT_MEMBERS - set(result))
    if missing:
        return "result is missing member(s): %s" % ", ".join(missing)

    predicates = result["predicates"]
    if predicates is not None:
        if not isinstance(predicates, dict):
            return "predicates is neither an object nor null"
        if set(predicates) != PREDICATE_MEMBERS:
            return "predicates is not exactly {R_A, R_B, R_C}"

    nonmeasurement = result["nonmeasurement"]
    if nonmeasurement is not None:
        if not isinstance(nonmeasurement, dict):
            return "nonmeasurement is neither an object nor null"
        stray = sorted(set(nonmeasurement) - NONMEASUREMENT_MEMBERS)
        if stray:
            return "nonmeasurement carries unknown member(s): %s" % ", ".join(stray)
        for required in ("reason", "detail"):
            if required not in nonmeasurement:
                return "nonmeasurement is missing %r" % required
        has_pointer = "json_pointer" in nonmeasurement
        if has_pointer != (nonmeasurement.get("reason")
                           == "numeric-preflight-violation"):
            return ("json_pointer is mandatory for numeric-preflight-violation "
                    "and permitted for no other reason")

    digests = result["verifier_digests"]
    if digests is not None:
        if not isinstance(digests, dict):
            return "verifier_digests is neither an object nor null"
        if set(digests) != VERIFIER_DIGEST_MEMBERS:
            return ("verifier_digests is not exactly the two entries "
                    "{class_verifier, class_verifier_contract}")

    if not isinstance(result["artifacts"], list):
        return "artifacts is not an array"
    for index, entry in enumerate(result["artifacts"]):
        if not isinstance(entry, dict):
            return "artifacts[%d] is not an object" % index
        if set(entry) != ARTIFACT_ENTRY_MEMBERS:
            return ("artifacts[%d] is not exactly the closed entry member set"
                    % index)
        ref = entry["artifact_ref"]
        if ref is not None:
            if not isinstance(ref, dict):
                return "artifacts[%d].artifact_ref is neither an object nor null" % index
            # CLOSURE ONLY, deliberately. `AD15-IR-18` states the closure and
            # pins its enforcement AT THE RESULT-SHAPE GATE, which rejects a
            # verdict carrying a member outside {record_id, chain_id}. It
            # creates no new REQUIREDNESS, and this validator must not either:
            # on the Source-A path the emitted value is a VERBATIM copy of a
            # frozen verdict, so a validator stricter than the gate could
            # condemn this evaluator's own conforming output. Requiredness on
            # `record_id` belongs to the frozen `$defs/artifact_ref` schema and
            # is the frozen verifier's business, not W1's.
            if not set(ref) <= ARTIFACT_REF_MEMBERS:
                return ("artifacts[%d].artifact_ref carries a member outside "
                        "the closed AD15-IR-18 set" % index)

    if not isinstance(result["withheld_reasons"], list):
        return "withheld_reasons is not an array"
    for index, entry in enumerate(result["withheld_reasons"]):
        if not isinstance(entry, dict) or set(entry) != WITHHELD_ENTRY_MEMBERS:
            return ("withheld_reasons[%d] is not exactly the closed AD15-IR-16 "
                    "entry {artifact_path, channel, reason}" % index)
    return None


def normative_projection(result: dict) -> dict:
    """The CLOSED cross-lane projection of contract 8.7, for harness duty 6.

    "Class 1 is compared as a CLOSED JSON VALUE, not field-by-field and never by
    string comparison of serializations. The projection is the result object
    with exactly these removed::

        nonmeasurement.detail
        evaluator_version
        verifier_digests.class_verifier
        artifacts[*].verifier_stderr_digest

    Everything else is retained -- including
    ``verifier_digests.class_verifier_contract``."

    Field-by-field duties grow by one entry per erratum and silently omit
    whatever nobody thought of. A closed projection inverts that: anything
    inside it is compared by construction, and anything a lane adds is an
    unknown member and therefore INVALID rather than quietly uncompared.

    The real cross-lane comparison is aggregate-harness duty 6, which sees both
    trees; contract 4 forbids a lane's runner from seeing its peer, so this
    function is deliberately PEER-FREE. What a lane can prove alone is that the
    model SEPARATES THE CLASSES -- that the projection is invariant under
    Class-3 and Class-4 substitution and moves under any Class-1 change.
    """
    out = dict(result)
    out.pop("evaluator_version", None)
    nonmeasurement = out.get("nonmeasurement")
    if isinstance(nonmeasurement, dict):
        trimmed = dict(nonmeasurement)
        trimmed.pop("detail", None)
        out["nonmeasurement"] = trimmed
    digests = out.get("verifier_digests")
    if isinstance(digests, dict):
        trimmed = dict(digests)
        trimmed.pop("class_verifier", None)
        out["verifier_digests"] = trimmed
    artifacts = out.get("artifacts")
    if isinstance(artifacts, list):
        projected = []
        for entry in artifacts:
            if isinstance(entry, dict):
                trimmed_entry = dict(entry)
                trimmed_entry.pop("verifier_stderr_digest", None)
                projected.append(trimmed_entry)
            else:
                projected.append(entry)
        out["artifacts"] = projected
    return out


def projection_bytes(result: dict) -> bytes:
    """The RFC 8785 canonical bytes of the 8.7 projection.

    "Equality is equality of the closed JSON value, OPERATIONALIZED THROUGH ITS
    RFC 8785 CANONICAL BYTES, so that member order, whitespace and number
    spelling cannot make two equal values compare unequal, nor two unequal
    values compare equal."
    """
    return jcs.canonicalize(normative_projection(result))


# --------------------------------------------------------------------------
# CLI (contract 8.1, 8.5)
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interop_eval.py",
        description=("AIREP v0.2 Python reference interop evaluator "
                     "(INTEROP_REFERENCE_EVALUATOR_CONTRACT.md). One invocation "
                     "evaluates exactly one scenario bundle and writes at most "
                     "one JSON result object to stdout."),
        # E4-1: the help carve-out is ONE EXACT SINGLE-TOKEN INVOCATION, so
        # `--help` is deliberately NOT registered as an option at all. It is
        # recognised in `main` only when it is the whole of argv; reaching the
        # parser with `--help` anywhere in it therefore fails as an unrecognised
        # argument, which is the exit-2 usage error the ruling requires. The
        # `-h` alias is likewise absent and prefix abbreviation is off, so `-h`
        # and `--hel` are ordinary usage errors too (A11).
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("--bundle")
    # Accepted only as a consistency assertion against the manifest roles (A1).
    parser.add_argument("--bindings")
    parser.add_argument("--independence-policy", dest="independence_policy")
    parser.add_argument("--revocation")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # E4-1: the meta-action is the SINGLE-TOKEN INVOCATION `--help` AND NOTHING
    # ELSE. "Exactly one flag wide" proved ambiguous and two lanes measurably
    # diverged on it, so the test is now an exact argv equality rather than a
    # membership test: `--help` exits 0 with human text and no result object;
    # `-h` is NOT an alias and is a usage error; and `--help` combined with any
    # other argument is a usage error too, because only the LONE help
    # invocation is carved out. Help text content and byte length are not a
    # parity requirement, so nothing here pins what is printed.
    if argv == HELP_INVOCATION:
        parser.print_help()
        return 0
    # argparse exits 2 on any usage error, raising SystemExit and bypassing
    # everything below, so no result object is ever written for one.
    args = parser.parse_args(argv)

    try:
        if args.bundle is None:
            raise UsageError("--bundle is required")
        result = evaluate_bundle(args)
    except UsageError as exc:
        warn("usage error: %s" % exc)
        return 2
    except BundleIdentityError as exc:
        # Identity was never established: silence on stdout (contract 8.5).
        warn("bundle identity: %s" % exc)
        return 1
    except NonMeasurement as exc:
        warn("%s: %s" % (exc.reason, exc.detail))
        if exc.scenario_id is None:
            # Unreachable by construction: NonMeasurement is only raised
            # downstream of an established identity. Fail closed rather than
            # emit a result object with an invented identity.
            warn("no bundle identity for an exit-3 result object")
            return 1
        write_result(dump_json(build_result(
            exc.scenario_id, exc.status, None, None, nonmeasurement_object(exc),
            exc.artifacts, exc.withheld_reasons, exc.verifier_digests)))
        return 3
    write_result(dump_json(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
