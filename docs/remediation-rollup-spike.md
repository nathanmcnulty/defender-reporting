# Remediation Rollup Spike

This note captures the current data boundary for remediation reporting and the next safe architectural step if we want to move from advisory-level reporting toward product-level patch rollups.

## Why this exists

The dashboard can now group remediation cards more consistently, but there is still a separate product question behind the feedback:

- users want to know what update they actually need
- some advisories map to multiple patch references for the same product
- the current export shape does not prove which patch is the latest applicable fix or the minimum sufficient fix

That means the UI can improve readability today, but it should not claim supersedence or minimum-patch semantics that the data does not actually encode.

## What the current data reliably supports

The current export and dashboard payload reliably preserve these remediation signals per vulnerability row:

- product scope: vendor plus software name
- recommendation scope key: `RecommendationReference`
- advisory title: `CveBatchTitle`
- update reference: `RecommendedSecurityUpdate`
- update identifier: `RecommendedSecurityUpdateId`
- update URL: `RecommendedSecurityUpdateUrl`
- platform scope: `OSPlatform`

Those fields are enough to build a stable remediation family model:

```text
remediation family = product scope + advisory family + platform
patch references = zero or more RecommendedSecurityUpdate values inside that family
```

This is the level the current dashboard can support honestly.

## What the current data does not prove

The current export shape does not reliably provide:

- an explicit supersedence chain between two updates for the same product
- a canonical vendor-defined "latest applicable patch" field
- a canonical minimum fixed version per product or per device
- release ordering semantics across multiple advisory references for the same product
- a guarantee that a numeric update reference such as `126348` is globally unique or self-describing

Because of that, the dashboard should not yet label a remediation as:

- `Latest patch`
- `Minimum required patch`
- `Superseded by ...`

unless a new data source is introduced to support those claims.

## Recommended model boundary

Keep the current remediation reporting model split into two layers.

### Layer 1: current supported model

Use this for the current dashboard and validation paths.

```text
RemediationFamily {
  scopeKey
  productLabel
  familyTitle
  platform
  patchReferences[]
  patchReferenceUrls[]
  deviceCount
  cveCount
  severitySummary
}
```

Rules:

- the title should be advisory-first when `CveBatchTitle` exists
- the product label should supply missing context when the advisory title is broad or absent
- patch references are supporting details, not the primary grouping key
- when a family has multiple patch references, show that deterministically rather than picking the first seen row

### Layer 2: future product lineage model

Do not implement this until a stronger source of truth exists.

```text
ProductPatchLineage {
  productKey
  platform
  advisories[]
  candidatePatches[]
  minimumSufficientPatch
  latestRecommendedPatch
  evidenceSource
  confidence
}
```

This second layer requires explicit evidence for patch ordering and sufficiency.

## Safe next implementation steps

If we want to keep improving readability without overclaiming, the next safe UI steps are:

1. Keep advisory title as the main remediation title.
2. Show one deterministic patch-reference summary badge only when it adds information.
3. If a remediation family has multiple patch references, show a summary such as `126348, 126354` or `126348 +N more` instead of a single arbitrary value.
4. Avoid surfacing internal recommendation keys as user-facing patch labels.

## What would unlock latest/minimum patch reporting

One of the following would be needed before the dashboard should show product-level latest/minimum patch semantics:

1. A Defender export field that explicitly identifies the fixed version or superseding update.
2. A vendor advisory ingestion path that maps multiple patch references into an ordered lineage.
3. A curated sidecar data set that declares product-specific supersedence rules.

Without one of those, the correct product-level message is still:

`This product is affected by this advisory family and these patch references were observed.`

That is materially better than showing a bare number, and it stays within what the data can defend.