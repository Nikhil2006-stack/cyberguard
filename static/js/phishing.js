// Phishing Analysis Interactive Handler
document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('phishingForm');
    const inputContent = document.getElementById('phishingInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const quickSampleBtns = document.querySelectorAll('.sample-btn');

    // 1-Click Sample Ingestion
    quickSampleBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            inputContent.value = this.dataset.sample;
            form.dispatchEvent(new Event('submit'));
        });
    });

    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            const text = inputContent.value.trim();
            if (!text) return;

            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Analyzing...';

            try {
                const response = await fetch('/api/phishing/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: text })
                });

                const json = await response.json();
                if (json.status === 'success') {
                    renderPhishingResults(json.data);
                } else {
                    alert('Analysis failed: ' + json.message);
                }
            } catch (err) {
                alert('Connection error during phishing analysis: ' + err.message);
            } finally {
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="bi bi-shield-shaded me-2"></i> Analyze Threat';
            }
        });
    }

    function renderPhishingResults(data) {
        resultsContainer.classList.remove('d-none');
        resultsContainer.scrollIntoView({ behavior: 'smooth' });

        document.getElementById('riskScoreValue').innerText = data.risk_score;
        document.getElementById('riskLevelBadge').innerText = data.risk_level.toUpperCase() + ' RISK';
        
        const badgeClasses = {
            'Critical': 'badge-critical',
            'High': 'badge-high',
            'Medium': 'badge-medium',
            'Low': 'badge-low'
        };
        const badgeEl = document.getElementById('riskLevelBadge');
        badgeEl.className = 'badge px-3 py-2 fs-6 ' + (badgeClasses[data.risk_level] || 'badge-low');

        // Meter progress bar
        const meter = document.getElementById('riskScoreBar');
        meter.style.width = data.risk_score + '%';
        if (data.risk_score >= 75) meter.className = 'progress-bar bg-danger';
        else if (data.risk_score >= 50) meter.className = 'progress-bar bg-warning';
        else if (data.risk_score >= 25) meter.className = 'progress-bar bg-info';
        else meter.className = 'progress-bar bg-success';

        // Evidence List
        const evidenceList = document.getElementById('evidenceList');
        evidenceList.innerHTML = '';
        if (data.evidence.length === 0) {
            evidenceList.innerHTML = '<div class="text-success"><i class="bi bi-check-circle me-2"></i> No suspicious keywords, deceptive domains, or urgency indicators detected.</div>';
        } else {
            data.evidence.forEach(item => {
                const div = document.createElement('div');
                div.className = 'p-3 mb-2 rounded border border-secondary bg-dark';
                div.innerHTML = `
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <strong class="text-info">${item.category}: ${item.trigger}</strong>
                        <span class="badge bg-danger">${item.impact}</span>
                    </div>
                    <div class="small text-light mb-1"><code>${escapeHtml(item.snippet)}</code></div>
                    <div class="small text-muted">${item.explanation}</div>
                `;
                evidenceList.appendChild(div);
            });
        }

        // Recommendations List
        const recList = document.getElementById('recommendationsList');
        recList.innerHTML = '';
        data.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.className = 'mb-1 text-light';
            li.innerHTML = `<i class="bi bi-shield-check text-success me-2"></i> ${rec}`;
            recList.appendChild(li);
        });

        // VirusTotal Status
        const vtBadge = document.getElementById('vtStatusBadge');
        if (vtBadge) {
            vtBadge.innerText = data.virustotal.status;
        }
    }

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
});
