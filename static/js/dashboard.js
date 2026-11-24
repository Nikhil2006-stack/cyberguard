// CYBERGUARD SOC Dashboard Live Charting & Periodic Polling
document.addEventListener('DOMContentLoaded', function () {
    // 1. Initialize Severity Distribution Doughnut Chart
    const severityCanvas = document.getElementById('severityChart');
    if (severityCanvas) {
        const crit = parseInt(severityCanvas.dataset.critical || 0);
        const high = parseInt(severityCanvas.dataset.high || 0);
        const med = parseInt(severityCanvas.dataset.medium || 0);
        const low = parseInt(severityCanvas.dataset.low || 0);
        const info = parseInt(severityCanvas.dataset.info || 0);

        new Chart(severityCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [crit, high, med, low, info],
                    backgroundColor: [
                        '#ff1744',
                        '#ffb300',
                        '#00f2fe',
                        '#00e676',
                        '#90caf9'
                    ],
                    borderColor: '#121c33',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8ca0ba', font: { size: 12 } }
                    }
                },
                cutout: '70%'
            }
        });
    }

    // 2. Initialize 7-Day Security Activity Line Chart
    const activityCanvas = document.getElementById('activityChart');
    if (activityCanvas && window.dashboardTimelineData) {
        const labels = window.dashboardTimelineData.map(item => item.date);
        const counts = window.dashboardTimelineData.map(item => item.count);

        new Chart(activityCanvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Security Events Logged',
                    data: counts,
                    fill: true,
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    borderColor: '#00f2fe',
                    tension: 0.35,
                    pointBackgroundColor: '#00f2fe',
                    pointBorderColor: '#fff',
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#8ca0ba' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#8ca0ba', stepSize: 1 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
});
