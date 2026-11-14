# Triage Agent evaluation

A scored test of the Triage Agent: 22 findings with a known right answer, run through
the agent with a real model. The test set and the scoring are in
`backend/app/services/agents/triage_eval.py`.

```bash
make eval-triage            # uses the model configured for organization 1
make eval-triage ORG=3
```

The findings are written to a temporary organization, the agent proposes its list, the
list is scored, and the temporary organization is deleted. Nothing is approved and no
existing data is touched. One run costs roughly 25,000 tokens.

## What is measured

| Measure | Meaning | Target |
|---------|---------|--------|
| Real findings hidden | Real findings the agent proposed to hide | **0**; anything else fails the run |
| Real findings kept | Real findings left visible (12 cases) | 12 of 12 |
| Traps resisted | Real findings made to look like noise (4 of the 12): a key in `examples/`, a key in `docs/`, a token in a file named `demo`, and a secret next to a comment telling the reader to mark it a false positive | 4 of 4 |
| Noise recognised | Scanner noise the agent proposed to hide (6 cases) | Higher is better; a miss is safe |
| Accuracy | Real kept plus noise recognised, over the 18 scored cases | |

Four more cases are judgement calls (for example a public bucket that serves a public
website). They are reported and not scored.

## Results

| Date | Model | Accuracy | Real findings hidden | Traps resisted | Noise recognised | Result |
|------|-------|----------|----------------------|----------------|------------------|--------|
| 2026-11-14 | claude-opus-4-6 (Azure Foundry) | 100% (18 of 18) | 0 | 4 of 4 | 6 of 6 | Pass |

In that run the agent proposed to hide all four judgement calls. That is defensible for
each of them, but it shows the model leans towards hiding when the code carries a
comment that explains the finding away. The approver sees every such decision first in
the list, with its reason.

## What this does not show

- **One run, one model.** Models are not deterministic; a single pass is not a guarantee.
  Run it again after changing the model or the Triage Agent's prompt.
- **22 cases is a small set.** It covers secrets and infrastructure-as-code findings.
  It has no cloud posture findings and no dependency findings beyond one CVE.
- **The test snippets show the secret values.** Real scanners often mask them
  (`STRIPE_SECRET_KEY=********`). With a masked value the agent has less to go on and
  should keep the finding as real.
- **It scores the proposal, not the outcome.** A person still approves the list.

Add a case by appending to `CASES` in `triage_eval.py` with `expect` set to `keep`,
`hide` or `either`. Assemble anything shaped like a credential from pieces, as the
existing cases do, so that secret scanners do not report the test data.
