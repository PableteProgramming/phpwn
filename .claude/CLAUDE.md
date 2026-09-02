# Repo rules — PHPwn

## 1. Scope lock: this directory only, read-only elsewhere

Never create, edit, delete, move, or rename any file outside `PHPwn/` — this includes the parent `BachelorArbeit/` directory (`thesis/`, its `.claude/CLAUDE.md`, or any sibling). This is an absolute restriction, no exceptions, no asking-around-it. Reading files outside `PHPwn/` for context or fact-checking is fine.

## 2. Explain, then confirm, before applying any change

Before making any change (inside `PHPwn/`), explain in chat: what you're about to do, why, and what impact/blast radius it has — then wait for explicit confirmation before applying it. Describing a change and then making it in the same turn does not count as asking.

## 3. Git operations are scoped to this repo (`PHPwn/`)

`git add`, `git commit`, and `git push` always refer to the `PHPwn/` repo — never the parent `BachelorArbeit` repo/tree. Consistent with Rule 1, no git operation should touch anything outside `PHPwn/`.

## 4. Test in a temp dir before applying any edit or fix

Before applying a code edit or fix, first reproduce/test it in a temporary directory (not the working tree) — build/run/whatever check is appropriate — and show me the actual output. Only apply the change to the real files after I've seen that output and confirmed.
