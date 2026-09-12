/**
 * Facts the marketing site publishes about the product, in one place.
 *
 * Every value here names the thing that produces it, so it can be refuted
 * rather than believed. `warden/tests/test_version_of_record.py` asserts the
 * version against `warden/__init__.py::__version__`.
 *
 * Why this file exists: the version of record was already guarded across the
 * root markdown documents, but the guard's surface list stopped there. The
 * site was never in it, so eleven stamps across seven files sat at `v6.8`
 * while the product shipped `7.9.0` — a full major version behind, on the
 * pages a buyer reads first. Hardcoding `7.9` eleven times would only reset
 * that clock; one import plus a test is what stops it recurring.
 */
export const PRODUCT = {
  /** warden/__init__.py::__version__ — the version of record. */
  version: "7.9.0",
  /** The short form used in badges and footers. */
  display: "v7.9",
  /** docker-compose.yml, count of top-level `services:` keys. */
  services: 24,
  /** site/public/openapi.json, count of `paths` — regenerate with scripts/export_openapi.py. */
  endpoints: 660,
} as const;
