# Fixture principles

Cybersecurity test fixtures are **not products**. They exist to help analysts confidently answer: **would we log this, and would we detect it, if it happened?**

These apply to this script and to every fixture in this family.

1. **One action, one canary, never a product.** This script creates one Graph draft and prints one canary. It is not a platform, suite, or dashboard.
2. **Field-level filters.** Hunt the canary, mailbox, time window, API, and message id. Any SIEM. Not “open this Elastic data view.”
3. **Say delay out loud.** Ingest is often late. Do not treat an empty search in the first minutes as a miss. Wait 15–30 minutes.
4. **Lab-only and loud on purpose.** Lab mailbox. Obvious `LAB-DRAFT-…` canary. Never sent. Not stealthy. Authorized testing only.
