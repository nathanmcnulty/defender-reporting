# Filter Redesign Spike Plan

This note captures the shared data and indexing model for the filter redesign spikes.
The goal is to compare two interaction models without accidentally comparing two different filtering engines.

## Why this exists

The current dashboard filter experience mixes two different models:

- device group, device tags, and device name are treated as cascading filters
- OS platform and severity are ordinary checkbox filters
- the filtered row set is still the primary data source for most reports and charts

That leads to two recurring problems:

- the UI feels inconsistent because some filters narrow available values and others do not
- the cascade logic is tightly coupled to DOM rendering and is easy to regress

The spikes should compare interaction models, not unrelated implementation differences.

## Shared assumptions for both spikes

- Add a 1 week preset alongside the existing month-based presets.
- Keep date filtering as the first coarse scope boundary.
- Treat device name as a search problem, not as a high-cardinality cascading checkbox list.
- Build one canonical filter state and one scoped row selection pipeline.
- Keep `filteredData` as the source for report rendering so the rest of the dashboard keeps working.

## Canonical filter state

Both spikes should use the same logical state shape even if the UI differs.

```text
datePreset: 1w | 1m | 3m | 6m | 12m | custom
startDate: yyyy-mm-dd | ''
endDate: yyyy-mm-dd | ''
rbacGroups: string[]
deviceTags: string[]
osPlatforms: string[]
severities: string[]
deviceSearch: string
```

Notes:

- empty arrays mean all values are included
- `deviceSearch` is a case-insensitive contains match against device name and device id
- device name should no longer be modeled as a giant explicit multi-select list in either spike

## Shared indexing sketch

The dashboard already denormalizes rows. The next step is to build a light-weight index layer once, after denormalization.

Recommended shared index objects:

```text
deviceCatalogByKey: Map<deviceKey, {
  deviceKey,
  deviceId,
  deviceName,
  normalizedGroup,
  tagValues,
  osPlatform,
  searchText
}>

rowIndexesByDeviceKey: Map<deviceKey, number[]>
deviceKeysByGroup: Map<group, Set<deviceKey>>
deviceKeysByTag: Map<tag, Set<deviceKey>>
deviceKeysByPlatform: Map<platform, Set<deviceKey>>
rowIndexesBySeverity: Map<severity, number[]>
facetCatalog: {
  filterRbacGroup: option metadata,
  filterDeviceTags: option metadata,
  filterOSPlatform: option metadata,
  filterSeverity: option metadata
}
staticFacetCounts: counts computed once from the full dataset
```

This is intentionally modest. It avoids a full bitmap engine while still removing repeated catalog rebuilding.

## Shared filtering pipeline

Both spikes should answer filtering in the same order:

1. Resolve the active date window from the preset or custom dates.
2. Scan rows once to apply date overlap rules.
3. Apply severity filters at the row level.
4. Apply device-scope filters by matching the row's device metadata:
   - group
   - tag
   - OS platform
   - device search text
5. Emit the final row list into `filteredData`.

This preserves existing report semantics while making the device-name path much cheaper than the current checkbox list.

## Shared cache plan

Two small caches are enough for the spikes:

- `presetRangeCache`: resolved start and end dates for 1w, 1m, 3m, 6m, and 12m
- `scopedRowCache`: final filtered row arrays keyed by the canonical filter-state key

The purpose is not to eliminate all scanning. The purpose is to make repeat interactions feel predictable and to isolate each spike's UI cost from the filtering engine.

## Branch B scope

Option B should prototype a scope-first experience:

- live facet counts for group, tag, OS platform, and severity
- zero-result options remain visible but are dimmed instead of disappearing
- device name becomes a scoped search box
- severity can remain multi-select, but it should behave like the other facets

The important behavior is that the low-cardinality facets feel connected and relevant.

## Branch C scope

Option C should prototype a stable explicit filter model:

- filter option lists remain visually stable
- selected filters are surfaced as chips or a compact summary with clear actions
- counts, if shown, are static full-dataset counts rather than live cross-facet counts
- device name still becomes a search box

The important behavior is that the filter panel stops moving under the user and stops implying smart cascade behavior.

## What to compare

The branch review should score both spikes on the same dimensions:

- apply latency after a filter change
- DOM stability while interacting with the panel
- how quickly users understand which values are still relevant
- whether users miss live relevant counts
- maintenance risk in `templates/dashboard.js`
- ease of explaining the model in one sentence

## Expected decision rule

If users clearly prefer the live-facet behavior and the code remains stable, ship B.

If user preference is mixed, ship C. The filter surface is unlikely to grow further, so the lower-maintenance model should win when the UX advantage of B is not decisive.