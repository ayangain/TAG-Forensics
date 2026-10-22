Canary: the playbook secret code is HERON-7.

# Network Security Paper Playbook

A working guide for writing and reviewing papers in the network security domain. It is built from the TAG-IDS submission to ISEA–ISAP, which received split reviews (one weak reject, one weak accept) and a final reject. Use it in three modes: before writing, before submitting, and when reviewing someone else's paper.

---

## 0. The five lessons in one page

1. **Consistency is not validity.** Months of numeric audits made the paper internally tidy, but reviewers rejected it on whether the evidence supports the claims. A clean paper with a weak evaluation still gets rejected.
2. **A metric that cannot fail is not a result.** If the method defines the ground truth, scoring 100 percent on it proves nothing. Both reviewers hit the 0 percent FCR circularity even after reframing.
3. **Independent ground truth is mandatory.** Labels must come from something the method never sees, such as a simulated attacker's true campaign chains, a real attack trace, or expert annotation.
4. **Single seed, three small networks, and few candidate pairs cannot carry strong claims.** Variance and confidence intervals are part of the result, not an optional extra.
5. **Reframing is not a substitute for restructuring.** Softening one paragraph while the abstract and conclusion keep the old claim is worse than no softening. The headline claim must be fixed everywhere or redesigned.

A sixth, procedural lesson: an AI co-author or reviewer tends to be too generous on verdicts. Treat any "likely accept" from it as a hypothesis and get a hostile human read before submission.

---

## 1. Before writing: claim design

☐ Write the central claim as one sentence that could be false. If no experiment could contradict it, rewrite it.

☐ Classify every headline number as one of: definitional, empirical, or illustrative. Definitional numbers such as "0 percent by construction" must never appear in the abstract as findings.

☐ For each claim, name the experiment that supports it and the result that would refute it.

☐ Decide the contribution type honestly: new formalism, new system, new measurement, or new attack or defense. Evaluation depth must match. A formalism paper still needs a non-trivial validation. A system paper needs realistic conditions.

☐ Keep scope tight. Three modules in 15 pages thins each one. If the page budget forces a choice, a rigorous evaluation of one module beats shallow coverage of three.

☐ Pick the venue early and read its CFP in full: page limit, double-blind rules, AI-use disclosure, formatting, track fit, deadline. Do this before the draft exists, not the week of the deadline.

---

## 2. Evaluation design

### 2.1 Ground truth

☐ Labels are generated independently of the method under test.

☐ The circularity test: could the method plausibly score below perfect on this metric? If not, the metric is tautological.

☐ Report precision, recall, and F1 against independent labels. Report false positive rate or false correlation rate only alongside recall, never alone. A method that rejects everything has zero false positives.

☐ Include a necessary-versus-sufficient discussion. A structural condition such as reachability is necessary for an attack chain but not sufficient. Two unrelated actors can share a valid path.

### 2.2 Data and simulation

☐ Prefer real alert streams from public datasets or replayed traces where possible. Overlay synthetic topology if no combined dataset exists, and say so.

☐ If simulating, document everything a reader needs to re-run it: topology generator, vulnerability assignment, attacker model and goals, timing model, topology change process, alert generation, sensor coverage, noise, clock skew, and random seeds.

☐ State what the simulator cannot capture and how that could bias each reported number.

☐ Release code and configuration, or state clearly why not.

### 2.3 Scale and statistics

☐ Multiple seeds per configuration. Thirty or more is a reasonable floor for simulation work, and more is cheap.

☐ Report mean with confidence interval or standard deviation for every headline number. If one experiment already uses many trials, apply the same standard everywhere.

☐ Use several network sizes with enough pairs or events per cell that percentages are meaningful. Sixty candidate pairs means one pair moves the rate by more than one point.

☐ Do not claim a trend across three points. Say "no systematic trend observed" or run enough sizes to fit one.

☐ Include a scaling test or an honest complexity analysis. Report runtime, memory, and asymptotic cost, including how cost grows with time windows, hosts, and alert volume.

### 2.4 Baselines

☐ Include baselines a skeptical reader would pick, not only easy ones.

☐ The strawman test: does the baseline degenerate? If a time-window correlator links nearly every candidate pair, the comparison shows nothing about the method. Check the baseline's behavior directly.

☐ Include an ablation that isolates each claimed mechanism. For a temporal method, compare against its static counterpart.

☐ Include at least one learning-based or statistical baseline when the related work discusses them.

### 2.5 Sensitivity and robustness

☐ Sweep every tunable parameter the result depends on, such as weights, thresholds, time windows, and sparsity levels. Equal weights are a choice, not a neutral baseline, and reviewers will ask.

☐ Test degradation under realistic imperfection: missing data, noisy alerts, clock skew, partial sensor coverage.

☐ Report failure modes, not only successes.

---

## 3. Metric and definition hygiene

☐ Every metric gets a formal definition with an explicit numerator and denominator. "False correlation rate" is ambiguous until you say which pairs are counted.

☐ Every class or label gets a formal definition. If a category like "Ambiguous" appears in results, it needs a precise rule.

☐ State the implemented semantics, not only the intended ones. For path-based methods, say whether paths must be time-monotone, whether union graphs are used, and how window boundaries are handled.

☐ Make prose, tables, and figures use the same denominator. If a table shows 70.3 percent next to a 71.0 percent class share, the prose cannot describe 70.3 percent of that class.

☐ Never equate absence of evidence with absence of coverage. "No alert" is not the same as "unmonitored."

☐ Validate any composite score externally. Weights chosen as equal thirds still need a sensitivity analysis, and the ranking methodology needs a rank statistic, not r-squared alone.

---

## 4. Framing and claims

☐ The abstract, introduction, results, conclusion, and limitations must make the same claim at the same strength. Audit all five after every framing change.

☐ Use calibrated verbs. Prefer "suggests," "is consistent with," and "in our simulations" over "proves," "confirms," and "eliminates."

☐ Do not use "proof-of-concept" as a shield and then make strong claims. Choose a posture and keep it.

☐ State the headline number's provenance in the abstract. A mean over best-per-configuration baselines is not "the rate for conventional correlators."

☐ Label self-assessed comparison tables as self-assessed.

☐ Limitations should name the real threats and say what each one could change in the results. A list of caveats that never connects to the numbers reads as boilerplate.

☐ Avoid reusing the same stock phrase across sections, and avoid loaded terms that collide with existing vocabulary in the paper.

---

## 5. Numeric and notation audit protocol

Run these as a separate pass from the validity review, and never mistake one for the other.

☐ Build a single source-of-truth table of every number in the paper with its origin in the run output.

☐ Trace each restated number to every place it appears: abstract, intro, results, figures, captions, conclusion.

☐ Check aggregate definitions. Mean of what, over what, with what weights?

☐ Check that figure legends and captions agree.

☐ Fix overloaded symbols. One symbol, one meaning, for the whole paper.

☐ Pick one notation scheme per concept. Do not layer plain-language glosses on top of symbols.

☐ Do not dismiss notation or definition items as cosmetic. Reviewers read them as evidence of rigor.

---

## 6. Venue compliance gate

☐ Page limit, including references and figures, verified in the compiled PDF.

☐ Double-blind: no author names, affiliations, emails, ORCIDs, acknowledgments, or identifying file metadata. Check the PDF properties too.

☐ Self-citation phrased neutrally, in the third person, with no "our previous work." Make sure the self-cited paper is not so central that it fingerprints authorship.

☐ AI-use disclosure requirements read and handled. If the venue demands disclosure in a section that blind review forbids, ask the organizers early.

☐ Reference list: no duplicates, citation keys stable, subject and year verified.

☐ Submission buffer of at least several days. A last-day submission leaves no room to fix what the final read finds.

---

## 7. Red-team questions to ask before submitting

Ask these as if you were Reviewer 2.

1. Is any headline number true by definition?
2. What is the ground truth and who generated it?
3. How many seeds, and what is the variance?
4. Could a trivial baseline get the same result?
5. Does the baseline degenerate?
6. What does each module add, shown by ablation?
7. What happens when inputs are missing, noisy, or adversarial?
8. What is the runtime and how does it scale?
9. Can I reproduce this from the paper alone?
10. Which claim in the abstract is the weakest, and is it softened?
11. Are there inconsistencies between prose, tables, and figures?
12. What would an attacker do that this method misses?

---

## 8. Reviewing other papers in this domain

Score each dimension and write at least one concrete sentence for each.

| Dimension | What to look for |
|---|---|
| Problem and novelty | Is the gap real and the positioning fair, or is the comparison table self-flattering? |
| Threat model | Is the attacker explicit, realistic, and adaptive where it should be? |
| Soundness | Is the method correct and are the definitions formal and complete? |
| Ground truth | Independent of the method? Could the method fail the metric? |
| Baselines | Strong, fair, and non-degenerate? Is there an ablation? |
| Statistics | Seeds, intervals, significance, and effect sizes? |
| Realism | Real traces or realistic simulation, and how large? |
| Reproducibility | Simulator, parameters, and code available? |
| Claims versus evidence | Does the abstract match what the results show? |
| Limitations | Honest and tied to the numbers? |

Decision heuristic: if a strong claim rests on a metric the method defines for itself, on one seed, or on a degenerate baseline, the recommendation is at best weak reject until the evaluation is repaired.

---

## 9. Working process with an AI co-author or reviewer

☐ Ask it explicitly for a hostile review, not a polish pass.

☐ Separate the passes: validity review first, then consistency audit, then readability, then compliance.

☐ Do not let a clean audit raise confidence in acceptance. Audits measure tidiness only.

☐ Check the AI's claims against the document and the run output. It can misread a figure, and it can also overlook a real inconsistency.

☐ Get at least one independent human read from someone who has not seen the paper, ideally someone who reviews for the target venue.

☐ Record resolved issues and decisions in a log so they are not re-raised, but also record the ones you chose to ignore and why, since reviewers may raise them.

---

## 10. Pre-submission gate

Do not submit until every line is true.

☐ Every headline claim is empirical, independently labeled, and statistically supported.

☐ Any definitional result is labeled as definitional everywhere, including the abstract.

☐ Metrics, classes, and path semantics are formally defined.

☐ Multiple seeds with intervals, plus scale and runtime evidence.

☐ A non-degenerate baseline set with an ablation.

☐ Sensitivity analysis on every tunable parameter.

☐ Simulator and attacker model documented well enough to reproduce.

☐ Abstract, conclusion, and limitations agree.

☐ Numeric and notation audit done.

☐ Venue compliance gate done.

☐ One independent hostile read done.

---

## Appendix: TAG-IDS reviewer comments mapped to fixes

| Reviewer concern | Fix to apply next time |
|---|---|
| 0 percent FCR is circular because TACV defines the Impossible class | Independent ground truth from simulated attacker chains and precision, recall, F1 for all methods |
| FCR and Ambiguous lack formal definitions | Formal definitions with numerator and denominator, and stated path semantics |
| Reachable path is necessary but not sufficient | Explicit discussion and a test with unrelated actors sharing a valid path |
| Single seed, three small networks, few pairs | Many seeds, more sizes, confidence intervals, same treatment as the log-loss study |
| Timing may have little effect, so the baseline may degenerate | Check baseline link rates directly and add stronger baselines |
| STS lacks external validation and the ranking method is unclear | Rank statistics, external validation, and weight sensitivity analysis |
| TBSQ equates no alert with unmonitored | Model sensor coverage separately from alert absence and evaluate PC, BSP, and placement |
| Simulator and attacker model not reproducible | Full documentation and released code |
| Exact source recovery lacks methodology | Document the method or drop the claim |
| No runtime or complexity analysis | Measure runtime and analyze scaling with hosts, windows, and alerts |
| Inconsistent definitions, notation, figures, and FCR values | Single source-of-truth numbers table and a notation pass, including items previously dismissed as minor |
| Table 1 is self-assessed | Label it as such |
| Soften claims | Calibrated verbs in abstract and conclusion, with headline provenance stated |
