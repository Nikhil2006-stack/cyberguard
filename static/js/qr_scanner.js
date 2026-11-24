// QR Code Scanner Interactive Handler
document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.getElementById('qrUploadForm');
    const qrFileInput = document.getElementById('qrFile');
    const uploadBtn = document.getElementById('uploadBtn');
    const resultCard = document.getElementById('qrResultCard');
    const testSampleBtns = document.querySelectorAll('.test-sample-qr-btn');

    // 1-Click Sample QR Testing
    testSampleBtns.forEach(btn => {
        btn.addEventListener('click', async function () {
            const qrType = this.dataset.type;
            const filename = `demo_${qrType}_qr.png`;
            
            uploadBtn.disabled = true;
            uploadBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Decoding Demo QR...';

            try {
                // Fetch sample image as blob
                const resp = await fetch(`/static/images/sample_qrs/${filename}`);
                const blob = await resp.blob();
                const formData = new FormData();
                formData.append('qr_image', blob, filename);

                const evalResp = await fetch('/api/qr/upload', {
                    method: 'POST',
                    body: formData
                });
                const json = await evalResp.json();
                if (json.status === 'success') {
                    renderQRResults(json.data);
                } else {
                    alert('QR Evaluation failed: ' + json.message);
                }
            } catch (err) {
                alert('Error loading sample QR: ' + err.message);
            } finally {
                uploadBtn.disabled = false;
                uploadBtn.innerHTML = '<i class="bi bi-upc-scan me-2"></i> Decode & Analyze QR';
            }
        });
    });

    if (uploadForm) {
        uploadForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            if (!qrFileInput.files.length) {
                alert('Please select an image file first.');
                return;
            }

            uploadBtn.disabled = true;
            uploadBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Processing Image...';

            const formData = new FormData();
            formData.append('qr_image', qrFileInput.files[0]);

            try {
                const resp = await fetch('/api/qr/upload', {
                    method: 'POST',
                    body: formData
                });
                const json = await resp.json();
                if (json.status === 'success') {
                    renderQRResults(json.data);
                } else {
                    alert('Error: ' + json.message);
                }
            } catch (err) {
                alert('Upload failed: ' + err.message);
            } finally {
                uploadBtn.disabled = false;
                uploadBtn.innerHTML = '<i class="bi bi-upc-scan me-2"></i> Decode & Analyze QR';
            }
        });
    }

    function renderQRResults(data) {
        resultCard.classList.remove('d-none');
        resultCard.scrollIntoView({ behavior: 'smooth' });

        document.getElementById('qrDecodedContent').innerText = data.decoded_content;
        document.getElementById('qrDecoderMethod').innerText = data.decoder_method || 'Native';
        document.getElementById('qrRiskScore').innerText = data.risk_score;

        const badgeEl = document.getElementById('qrRiskBadge');
        badgeEl.innerText = data.risk_level.toUpperCase() + ' RISK';
        const badgeClasses = {
            'Critical': 'badge-critical',
            'High': 'badge-high',
            'Medium': 'badge-medium',
            'Low': 'badge-low'
        };
        badgeEl.className = 'badge px-3 py-2 ' + (badgeClasses[data.risk_level] || 'badge-low');

        // Findings
        const findingsList = document.getElementById('qrFindingsList');
        findingsList.innerHTML = '';
        if (!data.findings || data.findings.length === 0) {
            findingsList.innerHTML = '<div class="text-success"><i class="bi bi-check-circle me-2"></i> No malicious redirection or structural anomalies detected.</div>';
        } else {
            data.findings.forEach(f => {
                const div = document.createElement('div');
                div.className = 'p-2 mb-2 rounded bg-dark border border-secondary';
                div.innerHTML = `<strong class="text-warning">${f.rule}</strong><div class="small text-light">${f.detail}</div>`;
                findingsList.appendChild(div);
            });
        }

        // Recommendations
        const recList = document.getElementById('qrRecommendationsList');
        recList.innerHTML = '';
        data.recommendations.forEach(r => {
            const li = document.createElement('li');
            li.className = 'small text-light mb-1';
            li.innerHTML = `<i class="bi bi-shield-check text-info me-2"></i> ${r}`;
            recList.appendChild(li);
        });
    }
});
