// Exact retained file identity, including the dashboard's persisted view query.
// Never treat all file: URLs as one origin. Hosted retains its original policy.
function isAllowedDashboardRequest(actual, origin, fileUrl) {
    if (!fileUrl) return actual.startsWith(origin + '/');
    try {
        const expected = new URL(fileUrl), observed = new URL(actual);
        if (expected.protocol !== 'file:' || observed.protocol !== 'file:') return false;
        if ([...observed.searchParams.keys()].some(key => key !== 'view') || observed.searchParams.getAll('view').length > 1) return false;
        expected.search = ''; expected.hash = '';
        observed.search = ''; observed.hash = '';
        return observed.href === expected.href;
    } catch { return false; }
}
module.exports = { isAllowedDashboardRequest };
