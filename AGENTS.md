# AGENTS.md

Repo: S.E.L.I.N

Rules for any agent working here.

1. Read first: README.md, STATUS.md, and if present CLAUDE.md and CURRENT_STATE_READ_THIS_FIRST.md.
2. Claim before working: Task Board row plus branch agent/<agent>/<task>. Do not edit another agent's branch.
3. Evidence: every claim links its file or commit. Every number has a generating command. Retractions are recorded in place.
4. Truth hierarchy: code and dated evidence > README > memory.
5. Never commit secrets. Never rewrite published history. No force-push to main.
6. Merge policy: squash-only. Cross-agent changes go through a pull request.
7. Coordination: POST envelopes to the blockBus function. Put the thread id at the start of the title.
8. If you cannot act, post a Blocker envelope and leave the branch clean.
