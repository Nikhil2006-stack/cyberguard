// Penetration Testing Lab Interactive Console
document.addEventListener('DOMContentLoaded', function () {
    const testButtons = document.querySelectorAll('.test-profile-btn');
    const reqDisplay = document.getElementById('rawRequestDisplay');
    const respDisplay = document.getElementById('rawResponseDisplay');
    const statusBadge = document.getElementById('responseStatusBadge');
    const verdictBox = document.getElementById('testVerdictBox');

    testButtons.forEach(btn => {
        btn.addEventListener('click', async function () {
            const endpointType = this.dataset.endpointType; // 'vulnerable' or 'secured'
            const profileId = this.dataset.profileId; // 1, 2, 3
            const url = `/lab/${endpointType}/profile/${profileId}`;

            // Update UI to indicate pending request
            if (statusBadge) statusBadge.className = 'badge bg-secondary';
            if (statusBadge) statusBadge.innerText = 'FETCHING...';
            
            const rawReq = `GET ${url} HTTP/1.1\nHost: localhost:5000\nUser-Agent: BurpSuite/Community-2026.1\nAccept: application/json\nCookie: session=[ACTIVE_SESSION_COOKIE]`;
            if (reqDisplay) reqDisplay.innerText = rawReq;

            try {
                const response = await fetch(url);
                const statusCode = response.status;
                const json = await response.json();

                // Format HTTP Response
                let rawResp = `HTTP/1.1 ${statusCode} ${response.statusText}\nContent-Type: application/json\n\n` + JSON.stringify(json, null, 2);
                if (respDisplay) respDisplay.innerText = rawResp;

                // Update Status Badge
                if (statusBadge) {
                    if (statusCode === 200) {
                        statusBadge.className = endpointType === 'vulnerable' && profileId !== '1' ? 'badge bg-danger' : 'badge bg-success';
                        statusBadge.innerText = `200 OK (${json.endpoint_status || 'SUCCESS'})`;
                    } else if (statusCode === 403) {
                        statusBadge.className = 'badge bg-success';
                        statusBadge.innerText = '403 FORBIDDEN (ACCESS BLOCKED)';
                    } else {
                        statusBadge.className = 'badge bg-warning';
                        statusBadge.innerText = `${statusCode} ERROR`;
                    }
                }

                // Render Educational Verdict
                if (verdictBox) {
                    if (endpointType === 'vulnerable' && profileId === '2') {
                        verdictBox.className = 'alert alert-danger mt-3';
                        verdictBox.innerHTML = `
                            <h5><i class="bi bi-exclamation-octagon-fill me-2"></i> IDOR EXPLOIT CONFIRMED!</h5>
                            <p class="mb-1"><strong>Root Cause:</strong> The vulnerable endpoint <code>/lab/vulnerable/profile/2</code> fetched Student B's confidential record without validating if you owned it!</p>
                            <p class="mb-0 small"><strong>Impact:</strong> Private phone numbers, emergency contact, academic notes, and account balance leaked to unauthorized caller.</p>
                        `;
                    } else if (endpointType === 'secured' && statusCode === 403) {
                        verdictBox.className = 'alert alert-success mt-3';
                        verdictBox.innerHTML = `
                            <h5><i class="bi bi-shield-check me-2"></i> AUTHORIZATION ENFORCED!</h5>
                            <p class="mb-1"><strong>Defense Active:</strong> The secured endpoint checked <code>current_user.id != profile.user_id</code> and blocked unauthorized access.</p>
                            <p class="mb-0 small"><strong>Remediation Status:</strong> Server-side ownership verification prevented the IDOR breach.</p>
                        `;
                    } else {
                        verdictBox.className = 'alert alert-info mt-3';
                        verdictBox.innerHTML = `
                            <strong>Request Result:</strong> HTTP ${statusCode}. ${json.message || 'Data retrieved successfully.'}
                        `;
                    }
                }

            } catch (err) {
                if (respDisplay) respDisplay.innerText = 'Network error executing request: ' + err.message;
            }
        });
    });
});
