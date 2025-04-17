// app/static/js/monitor.js
document.addEventListener('DOMContentLoaded', function() {
    // Debug flag - set to true to see detailed logs
    const DEBUG = true;

    function debug(...args) {
        if (DEBUG) {
            console.log(...args);
        }
    }

    // Socket.io setup - make sure we're using the right namespace
    const socket = io({
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        timeout: 20000
    });
    debug('Initializing Socket.IO connection');
    
    // Store traffic statistics
    let trafficStats = {
        protocols: { tcp: 0, udp: 0, icmp: 0, other: 0 },
        services: { http: 0, https: 0, dns: 0, smtp: 0, other: 0 },
        alerts: { high: 0, medium: 0, low: 0 }
    };
    
    // Traffic history for line chart
    const maxDataPoints = 30;
    let trafficHistory = {
        labels: Array(maxDataPoints).fill(''),
        data: Array(maxDataPoints).fill(0)
    };
    let packetsPerSecond = 0;
    let lastSecondPackets = 0;
    
    // Initialize charts
    let trafficChart, attackChart, liveTrafficChart;
    
    // Initialize charts on page load
    initCharts();
    
    // Update charts periodically
    setInterval(updateChartsData, 1000); // Update every second
    
    // Connect to Socket.IO server
    socket.on('connect', function() {
        debug('Connected to SocketIO server');
        
        // Notify user
        addStatusMessage('Connected to monitoring server');
        
        // Start the monitoring (send start_monitoring event)
        debug('Sending start_monitoring event');
        socket.emit('start_monitoring');
    });
    
    // Handle errors
    socket.on('connect_error', function(error) {
        console.error('Connection error:', error);
        addStatusMessage('Connection error: ' + error.message, 'error');
    });
    
    socket.on('disconnect', function() {
        console.error('Disconnected from server');
        addStatusMessage('Disconnected from server', 'error');
    });
    
    socket.on('monitoring_error', function(data) {
        console.error('Monitoring error:', data.error);
        addStatusMessage('Monitoring error: ' + data.error, 'error');
    });
    
    // Handle monitoring status
    socket.on('monitoring_started', function(data) {
        debug('Received monitoring_started:', data);
        if (data.status === 'success') {
            console.log('Monitoring started successfully');
            addStatusMessage('Monitoring started successfully');
        } else if (data.status === 'already_running') {
            console.log('Monitoring was already running');
            addStatusMessage('Monitoring was already running');
        }
    });
    
    socket.on('monitoring_status', function(data) {
        debug('Received monitoring_status:', data);
        addStatusMessage(`Monitoring status: ${data.status}`);
    });
    
    socket.on('monitoring_stopped', function(data) {
        debug('Received monitoring_stopped:', data);
        console.log('Monitoring stopped');
        addStatusMessage('Monitoring stopped');
    });
    
    // Listen for ANY event (helps with debugging)
    socket.onAny((eventName, ...args) => {
        debug(`Received event: ${eventName}`, args);
    });
    
    // Handle new packet data - try both 'new_packet' and other possible event names
    socket.on('new_packet', function(packet) {
        debug('Received new_packet event:', packet);
        processPacket(packet);
    });
    
    // Also try the event name without the namespace
    socket.on('packet', function(packet) {
        debug('Received packet event:', packet);
        processPacket(packet);
    });
    
    // Also listen for 'packet_data' in case that's what the server is emitting
    socket.on('packet_data', function(packet) {
        debug('Received packet_data event:', packet);
        processPacket(packet);
    });
    
    function processPacket(packet) {
        // Increment packets counter
        lastSecondPackets++;
        
        // Update protocol stats
        updateProtocolStats(packet);
        
        // Create table row for packet display
        addPacketToTable(packet);
        
        // Add notification
        addStatusMessage(`New packet: ${packet.srcip} → ${packet.dstip} (${packet.proto})`, 'info');
    }
    
    function initCharts() {
        debug('Initializing charts');
        
        // Traffic composition pie chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(trafficCtx, {
            type: 'pie',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e']
                }]
            },
            options: {
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true
                        }
                    }
                }
            }
        });

        // Attack distribution bar chart
        const attackCtx = document.getElementById('attackChart').getContext('2d');
        attackChart = new Chart(attackCtx, {
            type: 'bar',
            data: {
                labels: ['HTTP', 'HTTPS', 'DNS', 'SMTP', 'Other'],
                datasets: [{
                    label: 'Traffic by Service',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: '#4e73df'
                }]
            },
            options: {
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // Live traffic line chart
        const liveTrafficCtx = document.getElementById('liveTrafficChart').getContext('2d');
        liveTrafficChart = new Chart(liveTrafficCtx, {
            type: 'line',
            data: {
                labels: trafficHistory.labels,
                datasets: [{
                    label: 'Packets per Second',
                    data: trafficHistory.data,
                    borderColor: '#4e73df',
                    backgroundColor: 'rgba(78, 115, 223, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 3,
                    pointHitRadius: 10,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        suggestedMax: 10
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        intersect: false,
                        mode: 'nearest'
                    }
                },
                animation: {
                    duration: 500
                }
            }
        });
        
        debug('Charts initialized');
    }
    
    function updateProtocolStats(packet) {
        // Update protocol statistics
        let proto = packet.proto ? packet.proto.toLowerCase() : 'other';
        
        switch (proto) {
            case 'tcp':
                trafficStats.protocols.tcp++;
                break;
            case 'udp':
                trafficStats.protocols.udp++;
                break;
            case 'icmp':
                trafficStats.protocols.icmp++;
                break;
            default:
                trafficStats.protocols.other++;
                break;
        }
        
        // Update service statistics based on port or service field
        const service = getServiceFromPacket(packet);
        switch (service) {
            case 'http':
                trafficStats.services.http++;
                break;
            case 'https':
                trafficStats.services.https++;
                break;
            case 'dns':
                trafficStats.services.dns++;
                break;
            case 'smtp':
                trafficStats.services.smtp++;
                break;
            default:
                trafficStats.services.other++;
                break;
        }
        
        // Update alerts based on risk score if available
        if (packet.risk_score !== undefined) {
            if (packet.risk_score > 0.7) {
                trafficStats.alerts.high++;
            } else if (packet.risk_score > 0.3) {
                trafficStats.alerts.medium++;
            } else {
                trafficStats.alerts.low++;
            }
        }
    }
    
    function updateChartsData() {
        debug(`Updating charts with ${lastSecondPackets} new packets`);
        
        // Update traffic composition chart
        trafficChart.data.datasets[0].data = [
            trafficStats.protocols.tcp,
            trafficStats.protocols.udp,
            trafficStats.protocols.icmp,
            trafficStats.protocols.other
        ];
        trafficChart.update('none'); // Update without animation
        
        // Update attack distribution chart
        attackChart.data.datasets[0].data = [
            trafficStats.services.http,
            trafficStats.services.https,
            trafficStats.services.dns,
            trafficStats.services.smtp,
            trafficStats.services.other
        ];
        attackChart.update('none'); // Update without animation
        
        // Update packets per second and traffic history
        packetsPerSecond = lastSecondPackets;
        lastSecondPackets = 0;
        
        // Add timestamp
        const now = new Date();
        const timeLabel = now.getHours().toString().padStart(2, '0') + ':' + 
                         now.getMinutes().toString().padStart(2, '0') + ':' + 
                         now.getSeconds().toString().padStart(2, '0');
        
        // Shift arrays to add new data
        trafficHistory.data.shift();
        trafficHistory.labels.shift();
        trafficHistory.data.push(packetsPerSecond);
        trafficHistory.labels.push(timeLabel);
        
        // Update live traffic chart
        liveTrafficChart.data.labels = trafficHistory.labels;
        liveTrafficChart.data.datasets[0].data = trafficHistory.data;
        
        // Adjust y-axis scale based on traffic volume
        const maxY = Math.max(...trafficHistory.data, 10);
        liveTrafficChart.options.scales.y.suggestedMax = maxY * 1.2;
        
        liveTrafficChart.update();
    }
    
    function addPacketToTable(packet) {
        // Create table row
        const row = document.createElement('tr');
        
        // Risk level coloring
        const riskScore = packet.risk_score !== undefined ? packet.risk_score : 0;
        let rowClass = '';
        
        if (riskScore > 0.7) {
            rowClass = 'table-danger';
        } else if (riskScore > 0.3) {
            rowClass = 'table-warning';
        }
        
        if (rowClass) {
            row.className = rowClass;
        }
        
        // Get current time if packet doesn't have timestamp
        const timestamp = packet.timestamp ? 
            new Date(packet.timestamp).toLocaleTimeString() : 
            new Date().toLocaleTimeString();
        
        // Format service/port info
        const proto = packet.proto ? packet.proto.toUpperCase() : 'UNKNOWN';
        const service = getServiceFromPacket(packet);
        const protoDisplay = service ? `${proto} (${service})` : proto;
        
        // Build row HTML
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${packet.srcip || 'Unknown'}</td>
            <td>${packet.dstip || 'Unknown'}</td>
            <td>${protoDisplay}</td>
            <td>
                <div class="progress">
                    <div class="progress-bar ${getRiskClass(riskScore)}" 
                         role="progressbar" 
                         style="width: ${(riskScore * 100)}%">
                        ${(riskScore * 100).toFixed(1)}%
                    </div>
                </div>
            </td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="investigatePacket('${packet.srcip || ''}', '${packet.dstip || ''}')">
                    Investigate
                </button>
            </td>
        `;
        
        // Add to table at the beginning (newest first)
        const tableBody = document.getElementById('packetTableBody');
        tableBody.insertBefore(row, tableBody.firstChild);
        
        // Keep only last 100 entries
        if (tableBody.children.length > 100) {
            tableBody.removeChild(tableBody.lastChild);
        }
    }
    
    function getServiceFromPacket(packet) {
        // Try to determine service from packet data
        if (packet.service) {
            return packet.service.toLowerCase();
        }
        
        // Try to determine from port numbers
        const sport = parseInt(packet.sport) || 0;
        const dport = parseInt(packet.dport) || 0;
        
        // Check common ports
        if (sport === 80 || dport === 80) return 'http';
        if (sport === 443 || dport === 443) return 'https';
        if (sport === 53 || dport === 53) return 'dns';
        if (sport === 25 || dport === 25) return 'smtp';
        
        // Unknown service
        return 'other';
    }
    
    function getRiskClass(riskScore) {
        if (riskScore > 0.7) return 'bg-danger';
        if (riskScore > 0.3) return 'bg-warning';
        return 'bg-success';
    }
    
    // Status message counter for unique IDs
    let messageCounter = 0;
    
    function addStatusMessage(message, type = 'info') {
        // Log to console
        debug(`[${type}] ${message}`);
        
        // Create notification area if it doesn't exist
        let notificationArea = document.getElementById('notification-area');
        if (!notificationArea) {
            notificationArea = document.createElement('div');
            notificationArea.id = 'notification-area';
            notificationArea.className = 'notification-area';
            notificationArea.style.position = 'fixed';
            notificationArea.style.bottom = '20px';
            notificationArea.style.right = '20px';
            notificationArea.style.zIndex = '1000';
            document.body.appendChild(notificationArea);
        }
        
        // Create toast notification
        const id = `toast-${messageCounter++}`;
        const toast = document.createElement('div');
        toast.id = id;
        toast.className = `toast fade show bg-${type === 'error' ? 'danger' : 'light'}`;
        toast.role = 'alert';
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        
        toast.innerHTML = `
            <div class="toast-header">
                <strong class="mr-auto">NIDS Monitor</strong>
                <small class="text-muted">${new Date().toLocaleTimeString()}</small>
                <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close"
                        onclick="document.getElementById('${id}').remove();">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="toast-body ${type === 'error' ? 'text-white' : ''}">
                ${message}
            </div>
        `;
        
        // Add to notification area
        notificationArea.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (document.getElementById(id)) {
                document.getElementById(id).remove();
            }
        }, 5000);
    }
});

// Global function used by the investigate button
function investigatePacket(srcIp, dstIp) {
    if (srcIp && dstIp) {
        window.location.href = `/monitoring/packets?src=${srcIp}&dst=${dstIp}`;
    } else {
        alert('Cannot investigate: Missing source or destination IP');
    }
}