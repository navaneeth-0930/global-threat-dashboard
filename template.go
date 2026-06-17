package main

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background: #0a0e1a; font-family: 'Courier New', monospace; }
        .glow-green { box-shadow: 0 0 20px rgba(0, 255, 136, 0.15); }
        .glow-red   { box-shadow: 0 0 20px rgba(255, 59, 59, 0.15); }
        .threat-row:hover { background: rgba(0, 255, 136, 0.05); }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .live-dot { animation: pulse-dot 1.5s infinite; }
        @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
        .scanline {
            position: fixed; top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(transparent, rgba(0,255,136,0.08), transparent);
            animation: scanline 8s linear infinite;
            pointer-events: none; z-index: 9999;
        }
    </style>
</head>
<body class="text-gray-300 min-h-screen">
<div class="scanline"></div>

<div class="border-b border-green-900 bg-black bg-opacity-60 px-6 py-3 flex items-center justify-between">
    <div class="flex items-center gap-3">
        <div class="w-2 h-2 rounded-full bg-green-400 live-dot"></div>
        <span class="text-green-400 font-bold tracking-widest text-sm">THREAT INTELLIGENCE COMMAND CENTER</span>
    </div>
    <div id="clock" class="text-green-600 text-xs tracking-widest"></div>
</div>

<div class="grid grid-cols-4 gap-4 p-6">
    <div class="bg-black bg-opacity-60 border border-green-900 rounded-lg p-4 glow-green">
        <div class="text-green-600 text-xs tracking-widest mb-1">TOTAL THREATS</div>
        <div id="stat-total" class="text-3xl font-bold text-green-400">—</div>
        <div class="text-gray-600 text-xs mt-1">all feeds combined</div>
    </div>
    <div class="bg-black bg-opacity-60 border border-red-900 rounded-lg p-4 glow-red">
        <div class="text-red-500 text-xs tracking-widest mb-1">MALWARE DOWNLOADS</div>
        <div id="stat-malware" class="text-3xl font-bold text-red-400">—</div>
        <div class="text-gray-600 text-xs mt-1">active malware hosts</div>
    </div>
    <div class="bg-black bg-opacity-60 border border-yellow-900 rounded-lg p-4">
        <div class="text-yellow-600 text-xs tracking-widest mb-1">PHISHING URLS</div>
        <div id="stat-phishing" class="text-3xl font-bold text-yellow-400">—</div>
        <div class="text-gray-600 text-xs mt-1">credential theft pages</div>
    </div>
    <div class="bg-black bg-opacity-60 border border-blue-900 rounded-lg p-4">
        <div class="text-blue-500 text-xs tracking-widest mb-1">LAST UPDATED</div>
        <div id="stat-updated" class="text-lg font-bold text-blue-400">—</div>
        <div class="text-gray-600 text-xs mt-1">feed sync time</div>
    </div>
</div>

<div class="grid grid-cols-3 gap-4 px-6">
    <div class="col-span-1 bg-black bg-opacity-60 border border-green-900 rounded-lg p-4">
        <div class="text-green-600 text-xs tracking-widest mb-4">THREAT TYPE BREAKDOWN</div>
        <canvas id="threatChart"></canvas>
    </div>
    <div class="col-span-2 bg-black bg-opacity-60 border border-green-900 rounded-lg p-4">
        <div class="flex items-center gap-2 mb-4">
            <div class="w-2 h-2 rounded-full bg-red-500 live-dot"></div>
            <span class="text-green-600 text-xs tracking-widest">LIVE THREAT FEED</span>
        </div>
        <div class="grid grid-cols-3 gap-2 text-xs text-gray-600 tracking-widest border-b border-green-900 pb-2 mb-2">
            <span>TYPE</span>
            <span class="col-span-2">INDICATOR</span>
        </div>
        <div id="threat-feed" class="space-y-1 max-h-80 overflow-y-auto"></div>
    </div>
</div>

<script>
function updateClock() {
    const now = new Date();
    document.getElementById('clock').textContent = now.toUTCString().replace('GMT', 'UTC');
}
setInterval(updateClock, 1000);
updateClock();

const ctx = document.getElementById('threatChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: [],
        datasets: [{ data: [], backgroundColor: ['#00ff88','#ff3b3b','#ffaa00','#3b9eff','#cc44ff'], borderColor: '#0a0e1a', borderWidth: 3 }]
    },
    options: { plugins: { legend: { labels: { color: '#6b7280', font: { family: 'Courier New', size: 11 } } } } }
});

async function refresh() {
    try {
        const res  = await fetch('/api/threats/json');
        const data = await res.json();

        document.getElementById('stat-total').textContent    = data.total.toLocaleString();
        document.getElementById('stat-malware').textContent  = (data.by_type['malware_download'] || 0).toLocaleString();
        document.getElementById('stat-phishing').textContent = (data.by_type['phishing'] || 0).toLocaleString();
        document.getElementById('stat-updated').textContent  = new Date(data.latest).toLocaleTimeString();

        chart.data.labels = Object.keys(data.by_type);
        chart.data.datasets[0].data = Object.values(data.by_type);
        chart.update();

        const feed = document.getElementById('threat-feed');
        feed.innerHTML = data.recent.map(function(t) {
            return '<div class="threat-row grid grid-cols-3 gap-2 text-xs py-1 border-b border-gray-900">'
                 + '<span class="text-green-500 truncate">' + t.threat_type + '</span>'
                 + '<span class="col-span-2 text-gray-400 truncate font-mono">' + t.indicator + '</span>'
                 + '</div>';
        }).join('');

    } catch(e) {
        console.error('Refresh error:', e);
    }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>`