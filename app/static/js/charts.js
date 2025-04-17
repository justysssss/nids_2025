// app/static/js/charts.js
let trafficChart, attackChart;

function initCharts() {
    // Traffic Composition Chart
    trafficChart = new Chart(document.getElementById('trafficChart'), {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc', '#858796']
            }]
        }
    });

    // Attack Distribution Chart
    attackChart = new Chart(document.getElementById('attackChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attack Count',
                data: [],
                backgroundColor: '#e74a3b'
            }]
        }
    });
    
    updateCharts();
    setInterval(updateCharts, 5000);
}

async function updateCharts() {
    // Update traffic stats
    const stats = await fetch('/api/stats').then(r => r.json());
    trafficChart.data.datasets[0].data = [
        stats.tcp_count, stats.udp_count, 
        stats.icmp_count, stats.other_count
    ];
    trafficChart.update();

    // Update attack distribution
    const attackData = await fetch('/api/attack-distribution').then(r => r.json());
    attackChart.data.labels = attackData.labels;
    attackChart.data.datasets[0].data = attackData.data;
    attackChart.update();
}
