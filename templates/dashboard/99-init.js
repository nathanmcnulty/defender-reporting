// =============================================================================
// PAGE INITIALIZATION
// =============================================================================

window.addEventListener('DOMContentLoaded', function() {
    initEvidenceTooltips();
    init().catch(error => {
        console.error('Dashboard initialization failed:', error);
        setDashboardStatus('Failed to initialize the dashboard. If you are using split-assets mode, open it from an HTTP host with the required asset files.', 'error');
    });
});