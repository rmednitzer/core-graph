# ADR-0001: Establish ADR practice for core-graph

## Status

Accepted (recorded retroactively 2026-05-27; numbering pre-dates this file).

## Context

The repository carries architectural decisions whose rationale would
otherwise be lost as the codebase grows. Reviewers, future contributors,
and auditors need a single, durable record of "why we built it this way"
that travels with the source and survives team turnover. Without a
convention, decisions are reconstructed from commit messages, PR
threads, and chat history -- none of which are guaranteed to remain
available.

ADRs (Architectural Decision Records) are the established pattern for
this: short, numbered, version-controlled markdown files capturing one
decision each. Examples in this tree (ADR-0002 onward) follow the
pattern de facto but no document recorded the convention itself.

## Decision

Adopt a lightweight MADR-style ADR convention:

* Location: `docs/architecture/adr/ADR-NNNN-<short-slug>.md`.
* Numbering: zero-padded four-digit sequence starting at 0001. Never
  renumber, never delete; superseded decisions are marked
  `Status: Superseded by ADR-NNNN` and a new ADR is added.
* Required sections: `Status`, `Context`, `Decision`, `Consequences`.
  Other sections (`Validated alignments`, `References`, etc.) are
  added as the decision warrants.
* Granularity: one ADR per substantive architectural choice. Bug
  fixes and routine refactors do not warrant ADRs; choices that
  change interfaces, invariants, threat models, or storage shape do.
* Revalidation: when a previously-accepted ADR is re-examined,
  append a dated follow-up section rather than editing the body --
  the record of the original decision must remain intact.

## Consequences

* Future contributors can locate the rationale for any architectural
  invariant by reading the relevant ADR rather than archaeology.
* ADRs are auditable artefacts: each one carries a Status field and
  a date, satisfying ISO 27001 Annex A.5.2 "documentation of
  information security policies and procedures" for the architecture
  layer.
* The numbering convention is fixed: ADR-0001 is this file; substantive
  decisions begin at ADR-0002. Renumbering existing files is
  prohibited.
* Existing ADRs (0002 through 0006) remain valid; this ADR retroactively
  codifies the convention they follow.

## References

* Michael Nygard, 2011: *Documenting Architecture Decisions*
  (the original ADR proposal).
* MADR (Markdown Any Decision Records) template: <https://adr.github.io/madr/>.
* ISO/IEC 27001:2022 Annex A.5.2 -- Information security policies must be
  documented and reviewed at planned intervals.
