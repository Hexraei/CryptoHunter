// ==========================================
// Analysis Results Page - JavaScript
// Dynamic Table & Card Updates + GSAP Animations
// ==========================================

// DOM Elements
const exportBtnWrapper = document.getElementById('exportBtnWrapper');
const exportDropdown = document.getElementById('exportDropdown');
const exportOptions = document.querySelectorAll('.export-option');
const tableRowsContainer = document.getElementById('tableRowsContainer');
const backBtn = document.getElementById('backBtn');

// Card value elements
const primitivesValue = document.getElementById('primitivesValue');
const protocolsValue = document.getElementById('protocolsValue');
const architectureValue = document.getElementById('architectureValue');

// ==========================================
// GSAP Page Load Animations
// ==========================================
function initPageAnimations() {
    // Check if GSAP is available
    if (typeof gsap === 'undefined') {
        console.log('GSAP not loaded, skipping animations');
        return;
    }

    // Set initial states
    gsap.set('.back-btn', { opacity: 0, x: -20 });
    gsap.set('.summary-header', { opacity: 0, y: -20 });
    gsap.set('.card-wrapper', { opacity: 0, y: 30 });
    gsap.set('.table-container', { opacity: 0, y: 40 });
    gsap.set('.export-btn-wrapper', { opacity: 0, scale: 0.9 });

    // Create timeline for coordinated animations
    const tl = gsap.timeline({ defaults: { ease: 'power2.out' } });

    // Animate elements in sequence
    tl.to('.back-btn', {
        opacity: 1,
        x: 0,
        duration: 0.4
    })
        .to('.summary-header', {
            opacity: 1,
            y: 0,
            duration: 0.4
        }, '-=0.2')
        .to('.card-wrapper', {
            opacity: 1,
            y: 0,
            duration: 0.5,
            stagger: 0.1
        }, '-=0.2')
        .to('.table-container', {
            opacity: 1,
            y: 0,
            duration: 0.5
        }, '-=0.3')
        .to('.export-btn-wrapper', {
            opacity: 1,
            scale: 1,
            duration: 0.3
        }, '-=0.2');
}

// ==========================================
// Microinteractions
// ==========================================
function initMicrointeractions() {
    // Card hover effects
    const cards = document.querySelectorAll('.card-wrapper');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to(card, {
                    y: -5,
                    scale: 1.02,
                    duration: 0.25,
                    ease: 'power2.out'
                });
                gsap.to(card.querySelector('.card-icon-bg'), {
                    scale: 1.1,
                    duration: 0.25
                });
            }
        });

        card.addEventListener('mouseleave', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to(card, {
                    y: 0,
                    scale: 1,
                    duration: 0.25,
                    ease: 'power2.out'
                });
                gsap.to(card.querySelector('.card-icon-bg'), {
                    scale: 1,
                    duration: 0.25
                });
            }
        });
    });

    // Export button hover
    if (exportBtnWrapper) {
        exportBtnWrapper.addEventListener('mouseenter', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to('.export-btn-bg', {
                    scale: 1.02,
                    duration: 0.2
                });
            }
        });

        exportBtnWrapper.addEventListener('mouseleave', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to('.export-btn-bg', {
                    scale: 1,
                    duration: 0.2
                });
            }
        });
    }

    // Back button hover
    if (backBtn) {
        backBtn.addEventListener('mouseenter', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to('.back-icon', {
                    x: -3,
                    duration: 0.2
                });
            }
        });

        backBtn.addEventListener('mouseleave', () => {
            if (typeof gsap !== 'undefined') {
                gsap.to('.back-icon', {
                    x: 0,
                    duration: 0.2
                });
            }
        });
    }
}

// ==========================================
// Back Button - Navigate to Upload Page
// ==========================================
if (backBtn) {
    backBtn.addEventListener('click', function () {
        // Add exit animation before navigating
        if (typeof gsap !== 'undefined') {
            gsap.to('.main-container', {
                opacity: 0,
                duration: 0.3,
                onComplete: () => {
                    window.location.href = '/cryptex';
                }
            });
        } else {
            window.location.href = '/cryptex';
        }
    });
}

// ==========================================
// Load Analysis Data from Firmware Upload
// ==========================================
function loadAnalysisData() {
    // Get stored analysis data from previous page (real API results)
    const cachedResults = sessionStorage.getItem('cryptoHunterResults');
    const jobId = sessionStorage.getItem('cryptoHunterJobId');

    if (cachedResults) {
        try {
            const apiData = JSON.parse(cachedResults);
            processAnalysisData(apiData);
            console.log('Analysis data loaded from cache:', apiData);
        } catch (error) {
            console.error('Error parsing analysis data:', error);
            setDefaultValues();
        }
    } else if (jobId) {
        // Fetch from API if not in cache
        fetch(`/api/results/${jobId}`)
            .then(res => res.json())
            .then(apiData => {
                processAnalysisData(apiData);
                console.log('Analysis data loaded from API:', apiData);
            })
            .catch(err => {
                console.error('Error fetching results:', err);
                setDefaultValues();
            });
    } else {
        console.log('No analysis data found. Using default values.');
        setDefaultValues();
    }
}

// Map API response format to UI display
function processAnalysisData(data) {
    // Map API response to UI format
    const uiData = {
        primitivesIdentified: data.summary?.crypto_count || 0,
        protocolsIdentified: data.protocols?.length || 0,
        architectureIdentified: data.summary?.architecture ||
            data.architecture_detection?.final?.architecture || 'Unknown',
        fileName: data.filename || 'firmware',
        table: (data.classifications || []).map(c => ({
            algorithm: c.class_name || c.name || 'Unknown',
            confidenceScore: `${Math.round((c.confidence || 0) * 100)}%`,
            notes: c.indicator || ''
        }))
    };

    // Update UI
    updateCardValues(uiData);
    updateTable(uiData.table);

    // Store for export
    window.analysisData = uiData;
    window.jobId = data.job_id;
}

// ==========================================
// Update Card Values
// ==========================================
function updateCardValues(data) {
    // Animate the number counting up
    if (primitivesValue) {
        animateValue(primitivesValue, 0, data.primitivesIdentified || 0, 1000);
    }
    if (protocolsValue) {
        animateValue(protocolsValue, 0, data.protocolsIdentified || 0, 1000);
    }
    if (architectureValue) {
        animateValue(architectureValue, 0, data.architectureIdentified || 0, 1000);
    }
}

// ==========================================
// Animate Number Value
// ==========================================
function animateValue(element, start, end, duration) {
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function for smooth animation
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        const current = Math.floor(start + (end - start) * easeOutQuart);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = end;
        }
    }

    requestAnimationFrame(update);
}

// ==========================================
// Update Table with Dynamic Rows
// ==========================================
function updateTable(tableData) {
    if (!tableRowsContainer) {
        console.error('Table rows container not found');
        return;
    }

    // Clear existing rows
    tableRowsContainer.innerHTML = '';

    // If no data, show empty state
    if (!tableData || tableData.length === 0) {
        const emptyRow = document.createElement('div');
        emptyRow.className = 'table-row empty-row';
        emptyRow.innerHTML = '<span class="empty-message">No algorithms detected</span>';
        tableRowsContainer.appendChild(emptyRow);
        return;
    }

    // Create rows for each algorithm
    tableData.forEach((item, index) => {
        const row = createTableRow(item, index);
        tableRowsContainer.appendChild(row);

        // Animate row entrance with GSAP
        if (typeof gsap !== 'undefined') {
            gsap.from(row, {
                opacity: 0,
                x: -20,
                duration: 0.4,
                delay: index * 0.08,
                ease: 'power2.out'
            });
        }
    });
}

// ==========================================
// Create Individual Table Row (Old Style)
// ==========================================
function createTableRow(data, index) {
    const row = document.createElement('div');
    row.className = 'table-row';

    // Algorithm name
    const algorithmSpan = document.createElement('span');
    algorithmSpan.className = 'row-algorithm';
    algorithmSpan.textContent = data.algorithm || 'Unknown';

    // Notes/Details
    const notesSpan = document.createElement('span');
    notesSpan.className = 'row-notes';
    notesSpan.textContent = data.notes ? `(${data.notes})` : '';

    // Confidence Score
    const confidenceSpan = document.createElement('span');
    confidenceSpan.className = 'row-confidence';
    confidenceSpan.textContent = data.confidenceScore || '0%';

    row.appendChild(algorithmSpan);
    row.appendChild(notesSpan);
    row.appendChild(confidenceSpan);

    // Add hover microinteraction
    row.addEventListener('mouseenter', () => {
        if (typeof gsap !== 'undefined') {
            gsap.to(row, {
                x: 5,
                backgroundColor: 'rgba(50, 50, 50, 0.5)',
                duration: 0.2
            });
        }
    });

    row.addEventListener('mouseleave', () => {
        if (typeof gsap !== 'undefined') {
            gsap.to(row, {
                x: 0,
                backgroundColor: 'rgba(33, 33, 33, 0.4)',
                duration: 0.2
            });
        }
    });

    return row;
}

// ==========================================
// Set Default Values
// ==========================================
function setDefaultValues() {
    const defaultValue = 0;

    if (primitivesValue) primitivesValue.textContent = defaultValue;
    if (protocolsValue) protocolsValue.textContent = defaultValue;
    if (architectureValue) architectureValue.textContent = defaultValue;

    // Set default table data
    const defaultTable = [
        { algorithm: 'No data', confidenceScore: '0%', notes: 'Upload a firmware file to analyze' }
    ];

    updateTable(defaultTable);

    window.analysisData = {
        primitivesIdentified: defaultValue,
        protocolsIdentified: defaultValue,
        architectureIdentified: defaultValue,
        fileName: 'Unknown',
        table: defaultTable
    };
}

// ==========================================
// Export Button Dropdown Functionality
// ==========================================

// Toggle dropdown on export button click
if (exportBtnWrapper) {
    exportBtnWrapper.addEventListener('click', function (e) {
        e.stopPropagation();
        const isOpen = exportDropdown.classList.contains('show');

        if (!isOpen) {
            exportDropdown.classList.add('show');
            // Animate dropdown open
            if (typeof gsap !== 'undefined') {
                gsap.from(exportDropdown, {
                    opacity: 0,
                    y: -10,
                    duration: 0.2
                });
                gsap.from('.export-option', {
                    opacity: 0,
                    x: -10,
                    stagger: 0.05,
                    duration: 0.2
                });
            }
        } else {
            exportDropdown.classList.remove('show');
        }
    });
}

// Close dropdown when clicking outside
document.addEventListener('click', function (e) {
    if (exportBtnWrapper && !exportBtnWrapper.contains(e.target)) {
        exportDropdown.classList.remove('show');
    }
});

// Handle export option clicks
exportOptions.forEach(option => {
    option.addEventListener('click', function (e) {
        e.stopPropagation();
        const format = this.getAttribute('data-format');

        // Add click feedback
        if (typeof gsap !== 'undefined') {
            gsap.to(this, {
                scale: 0.95,
                duration: 0.1,
                yoyo: true,
                repeat: 1,
                onComplete: () => {
                    downloadReport(format);
                    exportDropdown.classList.remove('show');
                }
            });
        } else {
            downloadReport(format);
            exportDropdown.classList.remove('show');
        }
    });
});

// ==========================================
// Download Report Function - Uses Backend API
// ==========================================
async function downloadReport(format) {
    const jobId = window.jobId || sessionStorage.getItem('cryptoHunterJobId');

    if (!jobId) {
        alert('No analysis results available for export');
        return;
    }

    // Map format to API endpoint
    const formatMap = {
        'json': 'json',
        'csv': 'csv',
        'xlsx': 'excel',
        'pdf': 'pdf'
    };

    const endpoint = `/api/export/${jobId}/${formatMap[format] || format}`;

    try {
        const response = await fetch(endpoint);

        if (!response.ok) {
            throw new Error(`Export failed: ${response.status}`);
        }

        // Get filename from header or generate one
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `cryptohunter_${jobId}.${format}`;
        if (contentDisposition) {
            const match = contentDisposition.match(/filename="?([^"]+)"?/);
            if (match) filename = match[1];
        }

        // Download the file
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

    } catch (error) {
        console.error('Export error:', error);
        alert('Failed to export: ' + error.message);
    }
}

// ==========================================
// Initialize on Page Load
// ==========================================
document.addEventListener('DOMContentLoaded', function () {
    initPageAnimations();
    initMicrointeractions();

    // Delay data load slightly to let initial animations start
    setTimeout(() => {
        loadAnalysisData();
    }, 300);
});
