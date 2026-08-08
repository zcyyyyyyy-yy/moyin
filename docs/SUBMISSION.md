# Moyin Submission Checklist

This note is a compact entry point for reviewers and for the OSC 2026
submission form. It intentionally keeps the project facts in one place so the
repository is easy to verify from GitHub.

## Repository

- GitHub: https://github.com/zcyyyyyyy-yy/moyin
- Primary language: MoonBit
- License: Apache-2.0
- Current focus: local-first privacy scanning, masking, tokenization, and
  privacy drift checks for logs, configs, and test data.

## Problem Solved

Moyin helps teams answer a simple but painful question before sharing files,
opening issues, committing examples, or publishing demos:

> Does this text contain private data or credentials that should not leave my
> machine?

It detects common sensitive values, explains why they were flagged, produces
masked or tokenized copies, and can compare a candidate file against a previous
privacy baseline without storing the original sensitive values.

## Reviewer Path

1. Install the MoonBit toolchain and Node.js 18+.
2. Clone the repository.
3. Run `npm run build`.
4. Run `npm run dev` and open `http://127.0.0.1:4173`.
5. Try the sample text in the browser UI, or run:

```bash
node cli/moyin.mjs examples/sample.log --tokenize --salt review-demo
```

## Core Features

- 13 detector categories, including phone, email, Chinese ID, bank card, IP,
  MAC, JWT, API keys, URL credentials, private keys, and custom terms.
- Validation-aware rules for values such as Chinese IDs, bank cards, and IPv4
  addresses.
- Two output modes: readable masking and deterministic salted tokenization.
- Chunked scanning for larger text.
- Privacy inventory reports that avoid storing raw sensitive values.
- Privacy drift comparison for CI or release checks.
- Browser UI, single-file CLI, stdin mode, and directory batch mode.

## Verification

The repository includes automated checks for the MoonBit packages, the CLI, and
the browser bundle. The latest GitHub Actions run should be visible from the
repository Actions tab.

Useful local commands:

```bash
moon test
moon fmt --check
moon check --target js
npm run build
```

## Competition Notes

- The project is built around MoonBit source code rather than treating MoonBit
  as a small wrapper.
- The README, architecture notes, security notes, contribution guide, examples,
  tests, and CI workflow are included for reproducibility.
- The project is intentionally useful as a small practical tool instead of a
  toy demo: it can be used before publishing logs, screenshots, config snippets,
  public issues, or training/demo data.
