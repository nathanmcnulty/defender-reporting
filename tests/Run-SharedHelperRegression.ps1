#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$TestName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Artifact', 'Store', 'Normalization', 'Benchmark', 'Generator', 'Validation', 'Other')]
    [string[]]$Category,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 10000)]
    [int]$StopAfter = 0,

    [Parameter(Mandatory = $false)]
    [string]$JUnitOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkSeriesTools.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Support.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Artifact.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Benchmark.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Normalization.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Other.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Store.ps1')
. (Join-Path $PSScriptRoot 'SharedHelperRegression.Validation.ps1')

function Invoke-SharedHelperRegressionTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$SuccessMessage
    )

    $testCommand = Get-Command -Name $Name -CommandType Function -ErrorAction Stop
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Output ("START {0}" -f $Name)
    & $testCommand
    $stopwatch.Stop()

    Write-Output ("  {0} ({1} ms)" -f $SuccessMessage, $stopwatch.ElapsedMilliseconds)
}

Write-Output 'Running shared-helper regression checks...'
$sharedHelperRegressionTests = @(
    @{ Name = 'Test-DashboardReferencePathReader'; SuccessMessage = 'Source/generated bounded reference metadata parity checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsOutputInsideSourceRoot'; SuccessMessage = 'Artifact manifest output-root guard checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsSourceRootOverlap'; SuccessMessage = 'Artifact manifest overlap guard checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsSourceFileOutsideSourceRoot'; SuccessMessage = 'Artifact manifest source-root boundary checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsCrossArtifactSourceConflict'; SuccessMessage = 'Artifact manifest cross-artifact conflict checks passed.' }
    @{ Name = 'Test-ArtifactManifestUsesContentFingerprint'; SuccessMessage = 'Artifact manifest fingerprint freshness checks passed.' }
    @{ Name = 'Test-ArtifactManifestRejectsGeneratedOutputWithoutFingerprint'; SuccessMessage = 'Artifact manifest fingerprint metadata checks passed.' }
    @{ Name = 'Test-CanonicalLayoutHelper'; SuccessMessage = 'Canonical layout helper checks passed.' }
    @{ Name = 'Test-FileSetFingerprintIgnoresTimestampChange'; SuccessMessage = 'File-set fingerprint stability checks passed.' }
    @{ Name = 'Test-NormalizedPayloadCacheRejectsManifestHashMismatch'; SuccessMessage = 'Normalized payload cache integrity checks passed.' }
    @{ Name = 'Test-NormalizedPayloadCacheVersionPreservesSourceData'; SuccessMessage = 'Normalized payload cache version and source-preservation checks passed.' }
    @{ Name = 'Test-NormalizedPayloadManifestSourceSummary'; SuccessMessage = 'Normalized payload source metadata checks passed.' }
    @{ Name = 'Test-SaveJSLibraryFileRefreshesEmptyCache'; SuccessMessage = 'JavaScript library cache refresh checks passed.' }
    @{ Name = 'Test-VulnContentStoreExistenceNeedsRef'; SuccessMessage = 'Content-store existence checks passed.' }
    @{ Name = 'Test-LocalExportArtifactCleanup'; SuccessMessage = 'Local export artifact cleanup checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreBackfillsCurrentRecordMetadata'; SuccessMessage = 'Machine store initialization checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreSupportsStateHashOnlyCurrentMap'; SuccessMessage = 'Machine store stateHash-only initialization checks passed.' }
    @{ Name = 'Test-MdeMachineRefreshPublishPlanSupportsStateHashOnlyCurrentMap'; SuccessMessage = 'Machine refresh plan stateHash-only checks passed.' }
    @{ Name = 'Test-MdeMachineRefreshFailureRemovesStagedFile'; SuccessMessage = 'Machine refresh failure cleanup checks passed.' }
    @{ Name = 'Test-MachineHistoryRemovePathsAllowsEmptyPublishedHistorySet'; SuccessMessage = 'Machine history cleanup empty-set checks passed.' }
    @{ Name = 'Test-RestoreStoreTransactionRejectsInvalidJournalShape'; SuccessMessage = 'Store transaction journal validation checks passed.' }
    @{ Name = 'Test-InitializeMachineHistoryStoreRejectsExpiredLegacyMigration'; SuccessMessage = 'Machine legacy migration cutoff checks passed.' }
    @{ Name = 'Test-InitializeAdvancedHuntingStoreRejectsExpiredLegacyMigration'; SuccessMessage = 'Advanced Hunting legacy migration cutoff checks passed.' }
    @{ Name = 'Test-PublishVulnerabilityHistoryStoreRejectsExpiredImplicitLegacyMigration'; SuccessMessage = 'Implicit vulnerability legacy migration cutoff checks passed.' }
    @{ Name = 'Test-PublishVulnerabilityHistoryStoreAllowsExplicitDownloadedLegacyFilesAfterCutoff'; SuccessMessage = 'Explicit vulnerability snapshot import cutoff checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportSmoke'; SuccessMessage = 'Bulk snapshot import smoke checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportSingleSnapshot'; SuccessMessage = 'Single-snapshot vulnerability import checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportMultipartSnapshot'; SuccessMessage = 'Multipart vulnerability import checks passed.' }
    @{ Name = 'Test-BulkSnapshotImportMergesIntoExistingCanonicalStore'; SuccessMessage = 'Existing-store vulnerability merge checks passed.' }
    @{ Name = 'Test-HttpRetryDelayHelperBehavior'; SuccessMessage = 'Retry delay helper checks passed.' }
    @{ Name = 'Test-WebRequestWithRetryTransientTransportBehavior'; SuccessMessage = 'Web request transient transport retry checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadMultipartNameUniqueness'; SuccessMessage = 'Multipart vulnerability download naming checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadStagingBehavior'; SuccessMessage = 'Multipart vulnerability download staging checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadRetriesEmptyBlob'; SuccessMessage = 'Multipart vulnerability empty-blob retry checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadEmptyBlobExhaustionBehavior'; SuccessMessage = 'Multipart vulnerability empty-blob retry exhaustion checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadMoveFailureCleanupBehavior'; SuccessMessage = 'Multipart vulnerability move-failure cleanup checks passed.' }
    @{ Name = 'Test-BulkVulnerabilitySnapshotDownloadCleanupBehavior'; SuccessMessage = 'Multipart vulnerability failed-download cleanup checks passed.' }
    @{ Name = 'Test-GetMdeAccessTokenReportsMissingConfigurationDiagnostic'; SuccessMessage = 'MDE token-source diagnostics checks passed.' }
    @{ Name = 'Test-GetMdeAccessTokenReportsAuthenticationContext'; SuccessMessage = 'MDE authentication context diagnostics checks passed.' }
    @{ Name = 'Test-NewMdeAccessTokenContextRejectsMissingExpirationMetadata'; SuccessMessage = 'MDE token expiration metadata checks passed.' }
    @{ Name = 'Test-MdeRequestHeaderRefreshesNearExpiryTokenContext'; SuccessMessage = 'MDE proactive token refresh checks passed.' }
    @{ Name = 'Test-MdeRequestHeaderKeepsExplicitAccessTokenContextStable'; SuccessMessage = 'Explicit MDE access token compatibility checks passed.' }
    @{ Name = 'Test-VulnCurrentFileRejectsDuplicateId'; SuccessMessage = 'Current-file duplicate Id checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutSkipsCanonicalQuarterlyStore'; SuccessMessage = 'Canonical quarterly history repair skip checks passed.' }
    @{ Name = 'Test-VulnStoreRequiresCanonicalRepairDetectsMalformedQuarterlyHistory'; SuccessMessage = 'Canonical quarterly history gate checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutRebuildsCanonicalQuarterlyRowSidecar'; SuccessMessage = 'Canonical quarterly rows-sidecar repair checks passed.' }
    @{ Name = 'Test-RepairVulnHistoryLayoutRepairsLegacyYearlyStore'; SuccessMessage = 'Legacy yearly history repair checks passed.' }
    @{ Name = 'Test-VulnHistoryFileValidatesQuarterlyHistoryDocument'; SuccessMessage = 'Quarterly history validation checks passed.' }
    @{ Name = 'Test-VulnCanonicalSignatureStability'; SuccessMessage = 'Canonical vulnerability signature checks passed.' }
    @{ Name = 'Test-MergeVulnObservedWindowRows'; SuccessMessage = 'Vulnerability observation merge checks passed.' }
    @{ Name = 'Test-ReadNormalizedVulnStoreRow'; SuccessMessage = 'Normalized vulnerability store reader checks passed.' }
    @{ Name = 'Test-ResolveNormalizedLookupIndexListHandlesScalarAndCollectionValues'; SuccessMessage = 'Lookup index list normalization checks passed.' }
    @{ Name = 'Test-ResolveNormalizedInventoryLookupSkipsEmptyInventoryData'; SuccessMessage = 'Inventory lookup normalization checks passed.' }
    @{ Name = 'Test-AddNormalizedCveUsesStableSeverityIndexLookup'; SuccessMessage = 'CVE severity lookup checks passed.' }
    @{ Name = 'Test-GetNormalizedRecordLookupHandlesScalarPathInputs'; SuccessMessage = 'Scalar path lookup checks passed.' }
    @{ Name = 'Test-InvokeNormalizationProgressCallbackUsesCountAndHeartbeat'; SuccessMessage = 'Normalization progress callback cadence checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataReportsContentStoreNormalizationPhase'; SuccessMessage = 'Content-store normalization phase callback checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataUsesStableDeviceIdFallback'; SuccessMessage = 'Stable device fallback identity checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataWritesExpectedRowCount'; SuccessMessage = 'Normalized vuln row-count checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataWritesDirectPayload'; SuccessMessage = 'Direct payload normalization checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataPreservesOptionalNvdFallback'; SuccessMessage = 'Optional NVD fallback normalization checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose'; SuccessMessage = 'Consuming payload-close lookup checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataContentStorePathDoesNotUseLegacyDictionaryReader'; SuccessMessage = 'Content-store streaming normalization checks passed.' }
    @{ Name = 'Test-RunbookBenchmarkPublicationReaderOptIn'; SuccessMessage = 'Runbook benchmark reader opt-in/default and trial flag forwarding checks passed.' }
    @{ Name = 'Test-RunbookExperimentalNormalizationCacheIsolation'; SuccessMessage = 'Experimental normalization cache isolation checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationRejectsIncompatibleMode'; SuccessMessage = 'Compiled normalization incompatible-mode guards passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataSupportsDirectMergeDeviceLookup'; SuccessMessage = 'Direct-merge device lookup success-path checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsOutOfOrderMachineStream'; SuccessMessage = 'Direct-merge device lookup exact-order guard checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsBlankDeviceId'; SuccessMessage = 'Direct-merge device lookup blank-device guard checks passed.' }
    @{ Name = 'Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose'; SuccessMessage = 'Content-store transient context-release and hosted-memory diagnostics checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataDeduplicatesRepeatedCveLookup'; SuccessMessage = 'Repeated CVE lookup deduplication checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataReportsZeroOnboardedContentStoreDiagnostic'; SuccessMessage = 'Zero-onboarded content-store diagnostics checks passed.' }
    @{ Name = 'Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUserMap'; SuccessMessage = 'Advanced Hunting device-user normalization checks passed.' }
    @{ Name = 'Test-NormalizedPayloadPreservesSingletonLookupArray'; SuccessMessage = 'Normalized payload lookup-array contents and cardinality checks passed.' }
    @{ Name = 'Test-WriteCombinedPayloadGzipPreservesColumnPayload'; SuccessMessage = 'Combined payload writer column-path checks passed.' }
    @{ Name = 'Test-NormalizedVulnColumnCacheRebuildsPayloadWithFreshLookups'; SuccessMessage = 'Normalized vuln column cache reuse checks passed.' }
    @{ Name = 'Test-NormalizedVulnColumnCacheRefreshesInventoryColumn'; SuccessMessage = 'Inventory-backed normalized vuln column cache reuse checks passed.' }
    @{ Name = 'Test-PipelineMemorySnapshotActualGcMetric'; SuccessMessage = 'Actual pipeline GC metric checks passed.' }
    @{ Name = 'Test-WriteBase64FileContentMatchesReferenceOutput'; SuccessMessage = 'Streamed base64 writer checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesAzureOnlyRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesCombinedRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkSeriesSummaryHandlesLocalOnlyRunMode'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkIncludesLocalRunHandlesLegacyInferenceShape'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-BenchmarkModeScenarioKeyHandlesLegacyModeMapping'; SuccessMessage = 'Benchmark series mode checks passed.' }
    @{ Name = 'Test-WriteProgressMarkerIncludesEtaWhenTotalCountKnown'; SuccessMessage = 'Progress marker ETA checks passed.' }
    @{ Name = 'Test-WriteCombinedPayloadGzipCanConsumeColumnLookupData'; SuccessMessage = 'Payload lookup consumption checks passed.' }
    @{ Name = 'Test-GetDashboardEmbeddedPayloadInspectionStreamsSelfContainedPayload'; SuccessMessage = 'Embedded payload inspection checks passed.' }
    @{ Name = 'Test-VulnDeviceProfileProjectionParity'; SuccessMessage = 'Complete collision-safe device profile projection checks passed.' }
    @{ Name = 'Test-LiveDashboardTenantBinding'; SuccessMessage = 'Offline owner demo tenant binding and private/local fallback checks passed.' }
    @{ Name = 'Test-VulnContentStoreRoundTrip'; SuccessMessage = 'Vulnerability content store round-trip checks passed.' }
    @{ Name = 'Test-ProceduralSyntheticDatasetGeneration'; SuccessMessage = 'Procedural synthetic generation and immutable overlay checks passed.' }
    @{ Name = 'Test-BulkSnapshotFreshImportProfilerParityAndGuards'; SuccessMessage = 'Fresh import profiler store parity, attribution, restoration and source guards passed.' }
    @{ Name = 'Test-MeasureStressRunWritesProgressAndFinalReport'; SuccessMessage = 'Measure-StressRun report persistence checks passed.' }
    @{ Name = 'Test-GenerateSyntheticLargeExportsUsesStablePlannerOrdering'; SuccessMessage = 'Synthetic planner ordering checks passed.' }
    @{ Name = 'Test-LargeDatasetValidationSemanticModeForcesFullReplay'; SuccessMessage = 'Large-dataset semantic sign-off checks passed.' }
    @{ Name = 'Test-HotPhaseReviewArtifactsModeSmoke'; SuccessMessage = 'Hot-phase review wrapper smoke checks passed.' }
    @{ Name = 'Test-GetDashboardTemplateContentAcceptsExplicitTemplatesPathWithEmptyDefaultRoot'; SuccessMessage = 'Dashboard template explicit-path checks passed.' }
    @{ Name = 'Test-ValidationHelperPayloadCanonicalization'; SuccessMessage = 'Validation helper payload-format checks passed.' }
    @{ Name = 'Test-ValidationHelperSourceCanonicalization'; SuccessMessage = 'Validation helper source canonicalization checks passed.' }
    @{ Name = 'Test-ValidationHelperStandaloneImport'; SuccessMessage = 'Validation helper standalone import checks passed.' }
    @{ Name = 'Test-DashboardValidationFailureExtendedEnrichmentGate'; SuccessMessage = 'Validation helper failure-gate checks passed.' }
    @{ Name = 'Test-StreamingDashboardAuditDetectsSourceMismatchDespitePayloadParity'; SuccessMessage = 'Streaming dashboard source-parity checks passed.' }
    @{ Name = 'Test-StreamingDashboardAuditReusesCachedPayloadSignatureSet'; SuccessMessage = 'Streaming dashboard payload-signature reuse checks passed.' }
    @{ Name = 'Test-DashboardAuditBootstrapsSyntheticLargePayloadCacheWithNormalizationLookup'; SuccessMessage = 'Dashboard synthetic large-dataset bootstrap checks passed.' }
    @{ Name = 'Test-DashboardValidationUsesStableFallbackDeviceProfile'; SuccessMessage = 'Dashboard validation fallback device profile checks passed.' }
    @{ Name = 'Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff'; SuccessMessage = 'Dashboard open-state audit checks passed.' }
    @{ Name = 'Test-DashboardValidationPreservesNoneSeverityData'; SuccessMessage = 'Dashboard none-severity validation checks passed.' }
    @{ Name = 'Test-DashboardSplitAssetsGenerationAndValidation'; SuccessMessage = 'Dashboard split-assets generation and validation checks passed.' }
    @{ Name = 'Test-DashboardValidateOnlyFailsWhenHostedPayloadMissing'; SuccessMessage = 'Hosted dashboard missing-payload negative checks passed.' }
    @{ Name = 'Test-PackageOnlyRejectsMismatchedNormalizedPayloadManifest'; SuccessMessage = 'Package-only manifest mismatch negative checks passed.' }
    @{ Name = 'Test-DashboardDualPackagingGenerationAndValidation'; SuccessMessage = 'Dashboard dual packaging generation and validation checks passed.' }
    @{ Name = 'Test-AdvancedHuntingBundleMatchesDedicatedReaderData'; SuccessMessage = 'Advanced Hunting bundle reader checks passed.' }
    @{ Name = 'Test-AdvancedHuntingBundleStringArrayFiltersSparseInputs'; SuccessMessage = 'Advanced Hunting bundle sparse string-array checks passed.' }
    @{ Name = 'Test-ReadNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'Machine tuple reader checks passed.' }
    @{ Name = 'Test-ReadFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'File-backed machine tuple reader checks passed.' }
    @{ Name = 'Test-ReadBucketedFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup'; SuccessMessage = 'Bucketed file-backed machine tuple reader checks passed.' }
    @{ Name = 'Test-NormalizationMachineTupleExtendsLegacyTuple'; SuccessMessage = 'Machine tuple extension checks passed.' }
    @{ Name = 'Test-LegacyMachineTupleFallbackPreservesProjectedRowMetadata'; SuccessMessage = 'Legacy tuple fallback checks passed.' }
    @{ Name = 'Test-SourceCveEnrichmentReadsExploitAvailabilityFromObjectRecord'; SuccessMessage = 'Source enrichment exploit-availability checks passed.' }
    @{ Name = 'Test-VulnPropertyHelpersSupportSupportedRowShapes'; SuccessMessage = 'Vulnerability property helper shape checks passed.' }
    @{ Name = 'Test-VulnObservedWindowCacheRoundTrip'; SuccessMessage = 'Observed-window cache round-trip checks passed.' }
    @{ Name = 'Test-FunctionAppWriteOutputNoEnumeratePreservesJObject'; SuccessMessage = 'Function App Write-Output -NoEnumerate checks passed.' }
    @{ Name = 'Test-FunctionExecutionInvocationDoesNotReplay'; SuccessMessage = 'Function non-idempotent invocation checks passed.' }
    @{ Name = 'Test-FunctionExecutionValidationRequiresTerminalEvidence'; SuccessMessage = 'Function terminal status and publication validation checks passed.' }
    @{ Name = 'Test-FunctionExecutionStatusSummaryIncludesNormalizationProgressInfo'; SuccessMessage = 'Function execution status summary metadata checks passed.' }
    @{ Name = 'Test-BenchmarkEvidenceEnvelopeWritesTransactionally'; SuccessMessage = 'Benchmark evidence schema and transactional publication checks passed.' }
    @{ Name = 'Test-GetBlobListPagination'; SuccessMessage = 'Blob listing pagination, encoding, empty-page, and cycle checks passed.' }
    @{ Name = 'Test-ProgressStallAssessmentDistinguishesSlowAndStalledWork'; SuccessMessage = 'Progress stall warning/failure checks passed.' }
    @{ Name = 'Test-FullGarbageCollectionRequestsLargeObjectHeapCompaction'; SuccessMessage = 'Large-object heap compaction checks passed.' }
    @{ Name = 'Test-AzureValidationHarnessRequiresExecutionGuardAndRestoration'; SuccessMessage = 'Azure validation guard and restoration checks passed.' }
    @{ Name = 'Test-AzureValidationRunbookByteRestoration'; SuccessMessage = 'Azure byte-exact candidate upload and failure restoration checks passed.' }
    @{ Name = 'Test-AzureValidationExpectedProjectionCountPreflight'; SuccessMessage = 'Azure expected projection count preflight checks passed.' }
    @{ Name = 'Test-AzureDashboardCandidateEvidenceRejectsIncompletePublication'; SuccessMessage = 'Azure candidate artifact evidence checks passed.' }
    @{ Name = 'Test-NormalizationExecutionPlanUsesCardinalityAndLegacyFallback'; SuccessMessage = 'Cardinality-aware normalization plan and legacy fallback checks passed.' }
    @{ Name = 'Test-BenchmarkWorkloadProfilesArePinned'; SuccessMessage = 'Versioned benchmark workload profile checks passed.' }
    @{ Name = 'Test-VulnPartitionStreamingParity'; SuccessMessage = 'Partition streaming interleaving, row/error parity and cleanup checks passed.' }
    @{ Name = 'Test-CompiledContentStringArrayRoundTrip'; SuccessMessage = 'Compiled content scalar and array round-trip checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationDeduplicatesDeviceProfile'; SuccessMessage = 'Compiled bounded duplicate device-profile parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationKeyComparerParity'; SuccessMessage = 'Compiled bounded severity and inventory comparer parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationCveEnrichmentComparerParity'; SuccessMessage = 'Compiled CVE enrichment comparer parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationPipeDelimitedKeyParity'; SuccessMessage = 'Compiled pipe-delimited lookup key parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationRequiresStagedFragment'; SuccessMessage = 'Compiled required staged fragment checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationRawPayloadParity'; SuccessMessage = 'Compiled bounded raw payload parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationNonStringPathParity'; SuccessMessage = 'Compiled bounded non-string path parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationScoreParity'; SuccessMessage = 'Compiled bounded CVSS score parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationMachineInfoParity'; SuccessMessage = 'Compiled bounded machine-info parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationHighCardinalityContract'; SuccessMessage = 'Compiled bounded high-cardinality payload contract checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationDateParity'; SuccessMessage = 'Compiled bounded date normalization parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationInvalidCalendarDateParity'; SuccessMessage = 'Compiled bounded invalid calendar date parity checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationCleansStagingOnFailure'; SuccessMessage = 'Compiled bounded staging cleanup checks passed.' }
    @{ Name = 'Test-CompiledBoundedStagingCleanupSurfacesDisposalAndProbeFailure'; SuccessMessage = 'Compiled bounded staging disposal and probe hardening checks passed.' }
    @{ Name = 'Test-CompiledBoundedContentNormalizationExpandedParity'; SuccessMessage = 'Compiled bounded content normalization expanded-parity checks passed.' }
    @{ Name = 'Test-SyntheticUploadManifestSelectsRawReplayArtifact'; SuccessMessage = 'Synthetic raw replay upload-manifest checks passed.' }
    @{ Name = 'Test-AtomicDashboardExecutableDiscovery'; SuccessMessage = 'Atomic executable discovery duplicate PATH, caller mock, and non-Windows fallback checks passed.' }
)

function Get-SharedHelperRegressionCategory {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -match 'ArtifactManifest|CanonicalLayout|FileSetFingerprint') { return 'Artifact' }
    if ($Name -match 'Synthetic|Benchmark|StressRun|ProgressMarker') { return 'Benchmark' }
    if ($Name -match 'Validation|Audit|Dashboard|Template|PackageOnly|HotPhase') { return 'Validation' }
    if ($Name -match 'Normalized|Normalization|Payload|Lookup|MachineTuple|CveEnrichment') { return 'Normalization' }
    if ($Name -match 'Vuln|Machine|AdvancedHunting|Store|Snapshot|Mde') { return 'Store' }
    if ($Name -match 'Generate') { return 'Generator' }
    return 'Other'
}

function Write-SharedHelperRegressionJUnit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Results
    )

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [void](New-Item -Path $parent -ItemType Directory -Force) }
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create([System.IO.Path]::GetFullPath($Path), $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('testsuite')
        $writer.WriteAttributeString('name', 'SharedHelperRegression')
        $writer.WriteAttributeString('tests', [string]$Results.Count)
        $writer.WriteAttributeString('failures', [string]@($Results | Where-Object { -not $_.Passed }).Count)
        $writer.WriteAttributeString('time', [string][math]::Round((($Results | Measure-Object -Property Seconds -Sum).Sum), 3))
        foreach ($result in $Results) {
            $errorMessage = [regex]::Replace(([regex]::Replace([string]$result.ErrorMessage, "`e\[[0-9;]*m", '')), '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
            $errorDetail = [regex]::Replace(([regex]::Replace([string]$result.ErrorDetail, "`e\[[0-9;]*m", '')), '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
            $writer.WriteStartElement('testcase')
            $writer.WriteAttributeString('name', [string]$result.Name)
            $writer.WriteAttributeString('classname', ('SharedHelperRegression.' + [string]$result.Category))
            $writer.WriteAttributeString('time', [string][math]::Round([double]$result.Seconds, 3))
            if (-not $result.Passed) {
                $writer.WriteStartElement('failure')
                $writer.WriteAttributeString('message', $errorMessage)
                $writer.WriteString($errorDetail)
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally { $writer.Dispose() }
}

$selectedTests = @($sharedHelperRegressionTests | Where-Object {
        $entry = $_
        $nameMatch = (-not $TestName -or @($TestName | Where-Object { $entry.Name -like $_ }).Count -gt 0)
        $testCategory = Get-SharedHelperRegressionCategory -Name $entry.Name
        $categoryMatch = (-not $Category -or $Category -contains $testCategory)
        $nameMatch -and $categoryMatch
    })
if ($StopAfter -gt 0) { $selectedTests = @($selectedTests | Select-Object -First $StopAfter) }
if ($selectedTests.Count -eq 0) { throw 'No shared-helper regression tests matched the requested selection.' }

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
Initialize-RegressionDashboardLibraryCache -BasePath (Join-Path $repoRoot '.local\shared-regression-fixtures')

$results = [System.Collections.Generic.List[object]]::new()
$failure = $null
foreach ($sharedHelperRegressionTest in $selectedTests) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-SharedHelperRegressionTest -Name $sharedHelperRegressionTest.Name -SuccessMessage $sharedHelperRegressionTest.SuccessMessage
        $stopwatch.Stop()
        $results.Add([PSCustomObject]@{ Name = $sharedHelperRegressionTest.Name; Category = Get-SharedHelperRegressionCategory $sharedHelperRegressionTest.Name; Seconds = $stopwatch.Elapsed.TotalSeconds; Passed = $true; ErrorMessage = ''; ErrorDetail = '' })
    }
    catch {
        $stopwatch.Stop()
        $failure = $_
        $results.Add([PSCustomObject]@{ Name = $sharedHelperRegressionTest.Name; Category = Get-SharedHelperRegressionCategory $sharedHelperRegressionTest.Name; Seconds = $stopwatch.Elapsed.TotalSeconds; Passed = $false; ErrorMessage = $_.Exception.Message; ErrorDetail = [string]$_ })
        break
    }
}

if (-not [string]::IsNullOrWhiteSpace($JUnitOutputPath)) { Write-SharedHelperRegressionJUnit -Path $JUnitOutputPath -Results $results }
if ($null -ne $failure) { throw $failure }

Write-Output 'Shared-helper regression checks passed.'
