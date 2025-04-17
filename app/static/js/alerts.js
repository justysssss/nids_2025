// Connect to WebSocket for real-time alerts
const socket = io();

// Listen for new alerts
socket.on('new_alert', function(alert) {
    // Create alert element
    const alertRow = createAlertRow(alert);
    
    // Add to table
    const tbody = document.querySelector('table tbody');
    if (tbody) {
        tbody.insertBefore(alertRow, tbody.firstChild);
        
        // Flash the new row
        alertRow.classList.add('highlight');
        setTimeout(() => alertRow.classList.remove('highlight'), 3000);
        
        // Update alert count if exists
        updateAlertCount();
    }
});

// Create a table row for an alert
function createAlertRow(alert) {
    const tr = document.createElement('tr');
    
    // Format timestamp
    const timestamp = new Date(alert.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Determine severity badge class
    const severityClasses = {
        'low': 'badge-info',
        'medium': 'badge-warning',
        'high': 'badge-danger',
        'critical': 'badge-dark'
    };
    
    tr.innerHTML = `
        <td>${formattedTime}</td>
        <td>
            <span class="badge ${severityClasses[alert.severity]}">
                ${alert.severity.toUpperCase()}
            </span>
        </td>
        <td>${alert.source_ip}</td>
        <td>${alert.destination_ip}</td>
        <td>${alert.attack_category}</td>
        <td>
            <span class="badge badge-warning">Pending</span>
        </td>
        <td>
            <a href="/alerts/${alert.id}" class="btn btn-sm btn-info">View</a>
        </td>
    `;
    
    return tr;
}

// Update the alert count in the navigation
function updateAlertCount() {
    const countElement = document.getElementById('alert-count');
    if (countElement) {
        const currentCount = parseInt(countElement.textContent) || 0;
        countElement.textContent = currentCount + 1;
    }
}

// Filter form submission
const filterForm = document.querySelector('form');
if (filterForm) {
    filterForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(filterForm);
        const params = new URLSearchParams(formData);
        window.location.search = params.toString();
    });
}

// Add CSS for highlight animation
const style = document.createElement('style');
style.textContent = `
    .highlight {
        animation: highlight-row 3s;
    }
    
    @keyframes highlight-row {
        0% { background-color: #fff3cd; }
        100% { background-color: transparent; }
    }
`;
document.head.appendChild(style);