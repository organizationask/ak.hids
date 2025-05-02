function setHostIP() {
    const hostIP = document.getElementById("host-ip").value;
    if (!hostIP) {
        alert("Please enter a valid IP address.");
        return;
    }

    fetch('/set_target_ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target_ip: hostIP }),
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to set host IP');
            }
            return response.json();
        })
        .then(data => {
            alert(data.message);
        })
        .catch(error => {
            console.error('Error setting host IP:', error);
            alert('Failed to set host IP.');
        });
}

async function fetchLogs() {
    const response = await fetch('/logs');
    const data = await response.json();
    const logsContainer = document.getElementById('logs');
    logsContainer.innerHTML = data.logs.map(entry => `<li>${entry}</li>`).join('');
}

function fetchAlerts() {
    fetch('/alerts')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch alerts');
            }
            return response.json();
        })
        .then(data => {
            const alertContainer = document.getElementById('alert-container');
            alertContainer.innerHTML = data.alerts.map(alert => `<div>${alert}</div>`).join("");
            alertContainer.scrollTop = alertContainer.scrollHeight; // Auto-scroll to the bottom
        })
        .catch(error => console.error('Error fetching alerts:', error));
}

function fetchHostLogs() {
    fetch('/host_logs')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch host logs');
            }
            return response.json();
        })
        .then(data => {
            const hostLogContainer = document.getElementById('host-log-container');
            hostLogContainer.innerHTML = data.logs.map(log => `<div>${log}</div>`).join("");
            hostLogContainer.scrollTop = hostLogContainer.scrollHeight; // Auto-scroll to the bottom
        })
        .catch(error => console.error('Error fetching host logs:', error));
}

function fetchHostAlerts() {
    fetch('/host_alerts')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch host alerts');
            }
            return response.json();
        })
        .then(data => {
            const hostAlertContainer = document.getElementById('host-alert-container');
            hostAlertContainer.innerHTML = data.alerts.map(alert => `<div>${alert}</div>`).join("");
            hostAlertContainer.scrollTop = hostAlertContainer.scrollHeight; // Auto-scroll to the bottom
        })
        .catch(error => console.error('Error fetching host alerts:', error));
}

async function fetchHostIP() {
    const response = await fetch('/host_ip');
    const data = await response.json();
    document.getElementById('host-ip').textContent = `Host IP: ${data.host_ip}`;
}

async function fetchIntrusions() {
    const response = await fetch('/intrusions');
    const data = await response.json();
    const intrusionsContainer = document.getElementById('detected-intrusions');
    intrusionsContainer.innerHTML = data.intrusions.map(entry => `<li>${entry}</li>`).join('');
}

setInterval(fetchLogs, 2000); // Fetch logs every 2 seconds
setInterval(fetchAlerts, 2000); // Fetch alerts every 2 seconds
setInterval(fetchHostLogs, 2000); // Fetch host logs every 2 seconds
setInterval(fetchHostAlerts, 2000); // Fetch host alerts every 2 seconds