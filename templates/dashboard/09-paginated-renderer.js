// =============================================================================
// PAGINATED RENDERING
// =============================================================================

class PaginatedRenderer {
    constructor(options) {
        this.containerId = options.containerId;
        this.scrollInfoId = options.scrollInfoId;
        this.pageSize = Number(options.pageSize) > 0 ? Number(options.pageSize) : 100;
        this.initialPageSize = Number(options.initialPageSize) > 0 ? Number(options.initialPageSize) : this.pageSize;
        this.appendRange = options.appendRange;
        this.resetContainer = typeof options.resetContainer === 'function'
            ? options.resetContainer
            : container => {
                container.innerHTML = '';
            };
        this.emptyStateHtml = typeof options.emptyStateHtml === 'string' ? options.emptyStateHtml : '';
        this.allItemsLabel = typeof options.allItemsLabel === 'string' && options.allItemsLabel
            ? options.allItemsLabel
            : 'rows';
        this.items = [];
        this.loadedCount = 0;
        this.expanded = false;
    }

    setItems(items) {
        this.items = Array.isArray(items) ? items : [];
    }

    getContainer() {
        return document.getElementById(this.containerId);
    }

    getState() {
        return {
            items: this.items,
            loadedCount: this.loadedCount,
            expanded: this.expanded
        };
    }

    render(options = {}) {
        if (Object.prototype.hasOwnProperty.call(options, 'items')) {
            this.setItems(options.items);
        }

        if (Object.prototype.hasOwnProperty.call(options, 'expanded')) {
            this.expanded = Boolean(options.expanded);
        }

        const container = this.getContainer();
        if (!container) {
            return this.getState();
        }

        this.resetContainer(container);

        if (this.items.length === 0) {
            this.loadedCount = 0;
            if (this.emptyStateHtml) {
                container.innerHTML = this.emptyStateHtml;
            }
            this.updateScrollInfo();
            return this.getState();
        }

        const endIdx = this.expanded
            ? this.items.length
            : Math.min(this.initialPageSize, this.items.length);
        this.appendRange(container, this.items, 0, endIdx);
        this.loadedCount = endIdx;
        this.updateScrollInfo();
        return this.getState();
    }

    loadMore() {
        const container = this.getContainer();
        if (!container || this.expanded || this.loadedCount >= this.items.length) {
            return this.getState();
        }

        const startIdx = this.loadedCount;
        const endIdx = Math.min(startIdx + this.pageSize, this.items.length);
        this.appendRange(container, this.items, startIdx, endIdx);
        this.loadedCount = endIdx;
        this.updateScrollInfo();
        return this.getState();
    }

    updateScrollInfo() {
        const scrollInfo = document.getElementById(this.scrollInfoId);
        if (!scrollInfo) {
            return;
        }

        if (this.expanded) {
            scrollInfo.textContent = `Showing all ${this.items.length} ${this.allItemsLabel}`;
            return;
        }

        scrollInfo.textContent = `Showing ${this.loadedCount} of ${this.items.length}`;
    }
}
