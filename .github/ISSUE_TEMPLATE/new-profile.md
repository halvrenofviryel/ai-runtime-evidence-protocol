---
name: New / proposed profile
about: Propose a binding profile for the shared catalogue, or share one you authored
title: "profile: <name> — "
labels: [profile, adoption]
---

> You do **not** need to open an issue to *use* a custom profile — a collision-resistant
> `profiles.<name>` block works today with no upstream registration (see `profiles/README.md`,
> "Authoring your own profile"). Open this only to propose one for the shared catalogue.

**Profile name** (collision-resistant — vendor / product / framework / reverse-DNS):

**Kind:** framework (maps to a regulation / standard / threat catalogue) · domain (industry fields)

**Fields it adds under `profiles.<name>`:**

**External anchors, if any** — and are they INDICATIVE (unverified against the primary source) or
verified?

**A worked record carrying the profile** (paste it), and confirm the neutrality test:
- [ ] deleting `profiles` from the record still validates against `core.schema.json`
