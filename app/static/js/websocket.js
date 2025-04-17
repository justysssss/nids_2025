// app/static/js/websocket.js
const socket = io();

// Store traffic statistics
let trafficStats = {
    protocols: { tcp: 0, udp: 0, other: 0 },
    services: { http: 0, ftp: 0, ssh: 0, smtp: 0, dns: 0, other: 0 },
    alerts: { high: 0, medium: 0, low: 0 }
};

// Initialize charts
let trafficChart, attackChart;

function initCharts() {
    // Traffic composition pie chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'pie',
        data: {
            labels: ['TCP', 'UDP', 'Other'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc']
            }]
        },
        options: {
            maintainAspectRatio: false,
            tooltips: { enabled: true },
            legend: { display: true }
        }
    });

    // Attack distribution bar chart
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['HTTP', 'FTP', 'SSH', 'SMTP', 'DNS', 'Other'],
            datasets: [{
                label: 'Alerts by Service',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: '#4e73df'
            }]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                yAxes: [{
                    ticks: { beginAtZero: true }
                }]
            }
        }
    });
}

// Update traffic statistics
function updateStats(packet) {
    // Update protocol stats
    if (packet.proto === 'tcp') trafficStats.protocols.tcp++;
    else if (packet.proto === 'udp') trafficStats.protocols.udp++;
    else trafficStats.protocols.other++;

    // Update service stats
    if (packet.service in trafficStats.services) {
        trafficStats.services[packet.service]++;
    } else {
        trafficStats.services.other++;
    }

    // Update alert stats based on risk score
    if (packet.risk_score > 0.8) trafficStats.alerts.high++;
    else if (packet.risk_score > 0.6) trafficStats.alerts.medium++;
    else trafficStats.alerts.low++;

    // Update charts
    updateCharts();
}

// Update chart displays
function updateCharts() {
    // Update traffic composition chart
    trafficChart.data.datasets[0].data = [
        trafficStats.protocols.tcp,
        trafficStats.protocols.udp,
        trafficStats.protocols.other
    ];
    trafficChart.update();

    // Update attack distribution chart
    attackChart.data.datasets[0].data = [
        trafficStats.services.http,
        trafficStats.services.ftp,
        trafficStats.services.ssh,
        trafficStats.services.smtp,
        trafficStats.services.dns,
        trafficStats.services.other
    ];
    attackChart.update();
}

// Handle new packet data
socket.on('new_packet', function(packet) {
    // Update statistics
    updateStats(packet);

    // Create table row
    const row = document.createElement('tr');
    
    // Risk level coloring
    const riskScore = packet.risk_score || 0;
    let rowClass = '';
    if (riskScore > 0.8) rowClass = 'table-danger';
    else if (riskScore > 0.6) rowClass = 'table-warning';
    
    row.className = rowClass;
    row.innerHTML = `
        <td>${new Date(packet.time * 1000).toLocaleTimeString()}</td>
        <td>${packet.srcip}</td>
        <td>${packet.dstip}</td>
        <td>${packet.proto.toUpperCase()} (${packet.service})</td>
        <td>
            <div class="progress">
                <div class="progress-bar ${rowClass || 'bg-success'}" 
                     role="progressbar" 
                     style="width: ${(riskScore * 100)}%">
                    ${(riskScore * 100).toFixed(1)}%
                </div>
            </div>
        </td>
        <td>
            <button class="btn btn-sm btn-primary" onclick="investigatePacket('${packet.srcip}', '${packet.dstip}')">
                Investigate
            </button>
        </td>
    `;
    
    const tableBody = document.getElementById('packetTableBody');
    tableBody.insertBefore(row, tableBody.firstChild);
    
    // Keep only last 100 entries
    if (tableBody.children.length > 100) {
        tableBody.removeChild(tableBody.lastChild);
    }
});

// Investigate packet details
function investigatePacket(srcIp, dstIp) {
    window.location.href = `/monitoring/packets?src=${srcIp}&dst=${dstIp}`;
}

// Initialize when document loads
document.addEventListener('DOMContentLoaded', initCharts);
