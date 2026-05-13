// =============================================================================
// VIRTUAL SCROLL FOR MODALS
// =============================================================================

/**
 * Lightweight virtual scroll for modal table bodies.
 * Only renders visible rows + a buffer, swapping rows on scroll.
 */
class VirtualModalTable {
    /**
     * @param {HTMLElement} scrollContainer - The scrollable parent (.modal-content)
     * @param {HTMLElement} tbody - The <tbody> element to virtualize
     * @param {Array} items - Source items for the virtualized table
     * @param {Function} rowBuilder - Builds a <tr> HTML string for an item
     * @param {number} rowHeight - Estimated row height in px
     */
    constructor(scrollContainer, tbody, items, rowBuilder, rowHeight = 36) {
        this.container = scrollContainer;
        this.tbody = tbody;
        this.items = items;
        this.rowBuilder = rowBuilder;
        this.rowHeight = rowHeight;
        this.bufferRows = 20;
        this.renderedStart = -1;
        this.renderedEnd = -1;
        this.renderPending = false;

        // Spacer rows for maintaining scroll height
        this.topSpacer = document.createElement('tr');
        this.bottomSpacer = document.createElement('tr');
        this.topSpacer.className = 'virtual-spacer';
        this.bottomSpacer.className = 'virtual-spacer';

        this._onScroll = this._onScroll.bind(this);
        this.container.addEventListener('scroll', this._onScroll, { passive: true });

        this.render();
    }

    _onScroll() {
        if (this.renderPending) {
            return;
        }

        this.renderPending = true;
        requestAnimationFrame(() => {
            this.renderPending = false;
            this.render();
        });
    }

    render() {
        const totalRows = this.items.length;
        if (totalRows === 0) return;

        const totalHeight = totalRows * this.rowHeight;
        const scrollTop = this.container.scrollTop;
        const viewHeight = this.container.clientHeight;

        // Find the table's offset relative to scroll container
        const tableRect = this.tbody.parentElement.getBoundingClientRect();
        const containerRect = this.container.getBoundingClientRect();
        const tableOffset = tableRect.top - containerRect.top + this.container.scrollTop;

        // Visible range within this table
        const relativeTop = Math.max(0, scrollTop - tableOffset);
        const relativeBottom = relativeTop + viewHeight;

        let startIdx = Math.floor(relativeTop / this.rowHeight) - this.bufferRows;
        let endIdx = Math.ceil(relativeBottom / this.rowHeight) + this.bufferRows;
        startIdx = Math.max(0, startIdx);
        endIdx = Math.min(totalRows, endIdx);

        // Skip re-render if range hasn't changed
        if (startIdx === this.renderedStart && endIdx === this.renderedEnd) return;
        this.renderedStart = startIdx;
        this.renderedEnd = endIdx;

        // Build visible rows
        const fragment = document.createDocumentFragment();

        // Top spacer
        const topH = startIdx * this.rowHeight;
        this.topSpacer.innerHTML = `<td colspan="99" class="virtual-spacer-cell" style="height:${topH}px;"></td>`;
        fragment.appendChild(this.topSpacer);

        // Visible rows
        const template = document.createElement('template');
        template.innerHTML = this.items.slice(startIdx, endIdx).map(this.rowBuilder).join('');
        fragment.appendChild(template.content);

        // Bottom spacer
        const bottomH = (totalRows - endIdx) * this.rowHeight;
        this.bottomSpacer.innerHTML = `<td colspan="99" class="virtual-spacer-cell" style="height:${bottomH}px;"></td>`;
        fragment.appendChild(this.bottomSpacer);

        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);
    }

    destroy() {
        this.container.removeEventListener('scroll', this._onScroll);
    }
}

// Track active virtual tables so we can clean up when modal closes
let activeVirtualTables = [];
let activeDevicesByRemediationVirtualTables = [];

function destroyManagedVirtualTables(registry) {
    registry.forEach(vt => vt.destroy());
    registry.length = 0;
}

function attachManagedVirtualTables(scrollContainer, vtRowData, registry) {
    for (const [vtId, config] of Object.entries(vtRowData)) {
        const tbody = scrollContainer.querySelector(`tbody[data-vt-id="${vtId}"]`);
        if (!tbody) {
            continue;
        }

        if (config.items.length > VIRTUAL_SCROLL_THRESHOLD) {
            registry.push(new VirtualModalTable(
                scrollContainer,
                tbody,
                config.items,
                config.rowBuilder,
                config.rowHeight || 36
            ));
        } else {
            tbody.innerHTML = config.items.map(config.rowBuilder).join('');
        }
    }
}