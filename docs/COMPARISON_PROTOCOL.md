# Tool comparison protocol

Status: development protocol, version 1. No comparative superiority or human-time reduction has been established.

## Scope

The first comparison measures **post-lock, fixed-region OCR parameter comparison**. It does not measure automatic document alignment, template setup, human review speed, production validation or an entire competing product. Every engine sees the same synthetic image pairs and the same encoded crop bytes. Its outputs remain observations; exact equality is computed from the original strings.

The public project is an independent personal prototype. Tests use fictional values, not company documents, patient records or interview material. Existing source-level human-first constraints remain mandatory. Benchmark R1 decisions are simulated and explicitly labelled; they are not evidence of actual human work.

## Primary metric and the 5% target

For fields whose two reference strings are present, let:

`supported_difference_recall = supported_differences / reference_differences`

A supported difference requires all of the following:

1. The two reference strings differ character for character.
2. The engine returns usable, non-abstained observations for both sides.
3. Both transcriptions exactly equal their respective original reference strings.
4. Deterministic comparison of those transcriptions returns different.

This is stricter than ordinary difference recall. Two incorrect transcriptions that happen to differ do not earn primary credit. Both metrics are reported, so historical ordinary-recall results are not silently redefined. Confidence scores are engine-specific and are not assumed calibrated to the same scale.

For a registered baseline with recall `R_base > 0`, the target is:

`R_candidate >= 1.05 * R_base`

For example, 80% to 84% is a relative 5% gain, or four percentage points. A zero baseline has no defined relative gain; no epsilon is added. When the baseline exceeds `20/21` (about 95.238%), this recall target is mathematically impossible. Reaching a ceiling does not authorize switching to speed, error reduction or another denominator after seeing the outcome.

Every report also gives sample counts, ordinary difference recall, false SAME, false positives, unresolved differences, raw and accepted pair-exact rates, abstention, system errors and structural rejection. A result must not improve the primary score by worsening safety or silently increasing the review burden.

## Sample accounting

- Freeze the complete `(case_id, parameter_id)` key set before execution. Duplicate, missing or unknown keys invalidate the comparison; they are not silently dropped or reweighted.
- Raw truth is nonempty text or an explicit `None` for missing. Do not strip whitespace, normalize case, convert numbers or reconstruct truth from OCR. Empty-string truth is rejected by this protocol rather than ambiguously treated as a missing or correctly read value.
- Structural missingness is a predeclared separate layer. A pair containing `None` cannot count as two correctly recognized parameters, even when both outputs are `None`.
- Difficult images whose reference values exist stay in the primary denominator. Blur, low contrast, timeout and rejection do not remove them.
- Each expected key must have an explicit valid, abstained or error result. An unavailable engine or unreviewed model is `NOT_EVALUATED`, not a zero-scoring defeated competitor.
- Record raw per-field outputs and failures, not only aggregates. Do not feed the reference strings, simulated R1 decisions or a rival's answers to any engine.

## First diagnostic: 32 synthetic panels

The first run is `DEVELOPMENT_ONLY`. It cannot return a confirmed 5% win, even if its point estimate exceeds the target. Its purpose is to check the comparator and discover concrete error modes.

Before execution, freeze a new seed, generator/source hashes, template, image/crop hashes, the following 32-panel design and all engine settings. There are four fields per panel, 128 fields total. This is a single fixed font/layout family, not 128 independent real-world documents.

| Prespecified family | Panels | What changes |
| --- | ---: | --- |
| Exact controls | 4 | All raw values match across different synthetic panel styles |
| Numeric/state changes | 4 | Digit and state substitutions |
| Negative sign | 4 | Leading minus signs on numeric values |
| Decimal precision | 4 | Equal numeric meaning, different character strings |
| Leading zero | 4 | Retained versus removed leading zeros |
| Unit and case | 4 | Unit or character-case differences |
| Missing structure | 4 | Left-only, right-only and both-side missing values |
| Image quality | 4 | Two low-contrast and two blurred panels; present truth remains in the denominator |

The original 28-field `HIDDEN_TEST` has been repeatedly inspected. Keep it as an exposed regression fixture; it is not a new blind or confirmatory test. New numbers from the same renderer also do not establish independence from the renderer's font and layout biases.

The first diagnostic compares two engine families, not four independent tools:

- Current ParamGuard/Tesseract pipeline, default PSM 7, with existing confidence and quality settings.
- Tesseract PSM 13 as a prespecified development ablation, not an already-promoted product change.
- Apple Vision accurate recognition with language correction enabled.
- The same Apple engine with correction disabled, reported alongside the enabled setting, not selected afterward as the weaker opponent.

Use the same frozen inset-8 PNG crops and image-quality gate for all configurations. Tesseract's existing confidence threshold remains 70; Apple receives no arbitrary cross-engine confidence threshold. Record its uncalibrated score and measure errors directly. No custom word list, answer-based vocabulary or label-dependent preprocessing is allowed.

The native helper is an optional local benchmark tool, not a production adapter or a project runtime requirement. It uses the installed Apple framework and SDK under Apple's proprietary terms, not an open-source weight license. It reads image bytes from stdin; it has no image URL, arbitrary source path or network-model option. Do not redistribute the framework, SDK or native executable. Alternative independent open-source engines remain in the researched queue.

Same hardware and crop bytes do not imply identical accelerators or confidence calibration. Record OS, framework revision, compiler, engine/configuration hashes and per-panel elapsed time. Apple may use platform-managed acceleration. Until resource assignment and complete timing scopes are matched, elapsed time is diagnostic only, not a comparative speed claim. No human time is inferred.

## Admission of the next independent engine

Research the current, representative model rather than choosing only a small or obsolete weak baseline. The initial queue includes RapidOCR/PaddleOCR with PP-OCRv6, docTR and EasyOCR. Check the fixed code release, model identity/hash, vocabulary, code and weight rights, default preprocessing and full installation/resource cost before running it. Upstream published percentages from different datasets are not this project's results.

The checked-in supply-chain inventory excludes operating-system frameworks and remains a separate, incomplete inventory. Its existing `tessdata-snum` unknown-license failure must not be waived because this optional benchmark can run. No framework or external model is admitted for redistribution by this protocol.

## Confirmation and continuing improvement

Development experiments may guide fixes and configuration proposals. A formal comparison must have a separate, predeclared confirmation plan before its data is inspected:

1. Specify the target input population, panel count and strata, sample-size rationale, fixed candidate and comparator versions, tuning budget, stopping rule and full cost boundary.
2. Split at the base-panel/source-family level. Font, crop and degradation variants of the same panel must not cross splits. A publicly reproducible seed is not proof that nobody inspected its answers.
3. For each baseline, estimate the paired statistic `T = R_candidate - 1.05 * R_base`. A point estimate alone or a test of improvement merely above zero is insufficient. Require the predeclared one-sided lower confidence bound to meet the 5% margin.
4. Account for within-panel dependence using panel-level paired resampling or another justified method. Prespecify the algorithm and repetition count. Small or degenerate samples, invalid intervals and insufficient budget remain inconclusive.
5. Prespecify simultaneous-comparison and repeated-confirmation error control. Repeatedly rerunning an unadjusted 95% interval until it passes is not confirmation. This first pilot implements no inferential pass/fail procedure.
6. Check safety and workload constraints together with the primary metric. No lock-before-AI violation, erased human decision, automatic release or accepted critical false SAME may be traded for a higher score. Report observed false positives, abstention, structural failures and additional review burden; zero observed errors does not prove zero future risk.
7. After a valid confirmed win, retain the former opponent and test set as regression checks, then select the next representative opponent. If a target is infeasible, blocked or out of scope, retain that finding instead of fabricating a win. Exposed confirmation data may become development/regression data, but not a fresh confirmation for the next tuned version.

For workflow efficiency, the primary outcome must instead be real total human time under the same complete R1 and follow-up requirements. Include preparation, locating, recording, rework and recovery. Randomized order and matched difficulty are necessary; no such participant study has been performed. That separate target cannot be replaced by CPU time, HTTP response bytes or click counts.

## Reproduction and evidence

The Python driver is `tools/compare_local_ocr.py`; the optional native helper is `tools/apple_vision_ocr.swift`. Compilation, images and results belong under a new `artifacts/comparison/` directory. The driver freezes inputs and code/configuration identities before recognition, uses a separate simulated locked task for each pipeline, checks equal crop hashes, and refuses to overwrite an existing execution.

Every comparison report must identify what ran, what did not run, the data/version boundary, actual commands and failures, and whether the 5% claim is untested, inconclusive, not met or confirmed. Only a separately reviewed confirmation workflow can support the final category. New comparison work is local; the earlier one-time GitHub upload does not authorize recurring publication.

## Primary references

- [Apple Vision text recognition](https://developer.apple.com/documentation/vision/recognizing-text-in-images): on-device accurate/fast modes and language handling.
- [Apple language-correction setting](https://developer.apple.com/documentation/vision/vnrecognizetextrequest/useslanguagecorrection): raw versus corrected observations.
- [Apple developer agreements](https://developer.apple.com/support/terms/): proprietary SDK/framework terms, not an open-source model license.
- [SciPy paired bootstrap](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.bootstrap.html): use the same sampled indices for paired observations; does not itself establish a valid study or sample size.
- [NIST simultaneous intervals](https://www.itl.nist.gov/div898/handbook/prc/section4/prc463.htm): why a predeclared set of comparisons requires simultaneous error control.

These references inform the protocol. They do not endorse this project or establish its performance.
