package main

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Global Threat Monitoring Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/globe.gl"></script>
    <style>
        body {
            background: #05070d;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .panel-title {
            letter-spacing: 0.1em;
            font-size: 11px;
        }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .live-dot { animation: pulse-dot 1.5s infinite; }
    </style>
</head>
<body class="text-gray-300">

    <!-- TOP STATUS BAR -->
    <div class="border-b border-gray-800 bg-black px-4 py-2 flex items-center justify-between text-xs overflow-x-auto whitespace-nowrap">
        <div class="flex items-center gap-6">
            <span class="text-green-400 font-bold tracking-widest">GLOBAL THREAT MONITORING COMMAND CENTER</span>
            <div id="world-clocks" class="flex items-center gap-5 text-gray-500"></div>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
            <div class="w-2 h-2 rounded-full bg-green-400 live-dot"></div>
            <span class="text-green-500">LIVE CONNECTION</span>
        </div>
    </div>

    <!-- THE THREE COLUMN GRID -->
    <div class="grid grid-cols-12 gap-2 p-2" style="height: calc(100vh - 40px);">

       <!-- LEFT COLUMN -->
<div class="col-span-2 bg-black border border-gray-800 rounded p-3 overflow-y-auto flex flex-col gap-4">

    <div>
        <div class="text-green-500 panel-title mb-2">CRYPTO — LIVE PRICES</div>
        <div id="crypto-prices" class="text-gray-500 text-xs">Loading...</div>
    </div>

    <div>
        <div class="text-blue-400 panel-title mb-2">ISS — LIVE POSITION</div>
        <div id="iss-position" class="text-gray-500 text-xs">Loading...</div>
    </div>

    <div>
        <div class="text-orange-400 panel-title mb-2">USGS — RECENT QUAKES</div>
        <div id="quake-list" class="text-gray-500 text-xs"></div>
    </div>

</div>

        <!-- CENTER COLUMN: takes up 7 of 12 grid units (the big one) -->
        <div class="col-span-7 bg-black border border-gray-800 rounded p-3 overflow-y-auto flex flex-col">
            <div id="globe-container" style="height: 320px; flex-shrink: 0;"></div>

            <div id="geo-legend" class="flex flex-wrap gap-2 text-xs py-2 border-b border-gray-800"></div>

            <div class="text-red-500 panel-title flex items-center gap-2 mb-2 mt-2">
                <div class="w-1.5 h-1.5 rounded-full bg-red-500 live-dot"></div>
                MALWARE — LIVE MALWARE DROP SITES
            </div>
            <div id="panel-malware"></div>
        </div>

        <!-- RIGHT COLUMN: takes up 3 of 12 grid units -->
        <div class="col-span-3 bg-black border border-gray-800 rounded p-3 overflow-y-auto flex flex-col gap-4">

            <div>
                <div class="text-yellow-500 panel-title flex items-center gap-2 mb-2">
                    <div class="w-1.5 h-1.5 rounded-full bg-yellow-500 live-dot"></div>
                    PHISHING — ACTIVE PHISHING URLS
                </div>
                <div id="panel-phishing"></div>
            </div>

            <div>
                <div class="text-orange-500 panel-title flex items-center gap-2 mb-2">
                    <div class="w-1.5 h-1.5 rounded-full bg-orange-500 live-dot"></div>
                    BOTNET — ACTIVE C2 SERVERS
                </div>
                <div id="panel-botnet"></div>
            </div>
            <div>
    <div class="text-purple-500 panel-title flex items-center gap-2 mb-2">
        <div class="w-1.5 h-1.5 rounded-full bg-purple-500 live-dot"></div>
        THREATFOX — TRACKED IOCs
    </div>
    <div id="panel-threatfox"></div>
</div>

        </div>

    </div>

<script>
    // ── World Clocks ──────────────────────────────────────────
    // Each entry: a label to display, and the official IANA time zone name
    // (these names come from a global standard — every OS and browser understands them)
    const CITIES = [
        { label: "LONDON",      tz: "Europe/London" },
        { label: "LOS ANGELES", tz: "America/Los_Angeles" },
        { label: "SÃO PAULO",   tz: "America/Sao_Paulo" },
        { label: "MOSCOW",      tz: "Europe/Moscow" },
        { label: "DUBAI",       tz: "Asia/Dubai" },
        { label: "MUMBAI",      tz: "Asia/Kolkata" },
        { label: "HONG KONG",   tz: "Asia/Hong_Kong" },
    ];

    function updateWorldClocks() {
        const now = new Date(); // one single instant, shared by everyone
        const container = document.getElementById('world-clocks');

        // .map() transforms each city object into an HTML string,
        // then .join('') glues all those strings together into one block
        container.innerHTML = CITIES.map(function(city) {
            // Intl.DateTimeFormat does the time zone conversion for us
            const timeStr = new Intl.DateTimeFormat('en-GB', {
                timeZone: city.tz,
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            }).format(now);

            return '<span>' + city.label + ' <span class="text-gray-300">' + timeStr + '</span></span>';
        }).join('');
    }

    updateWorldClocks();
    setInterval(updateWorldClocks, 1000); // re-run every second, just like a real clock

    // ── Reusable Panel Renderer ──────────────────────────────
    // containerId: the HTML element's id where this panel will be drawn
    // columns: an array of objects like { label: "Domain", key: "domain" }
    //          "label" is what the user SEES, "key" is the property name in the data
    // rows: an array of data objects, e.g. [{ domain: "evil.com", ip: "1.2.3.4" }]
    function renderPanel(containerId, columns, rows) {
        const container = document.getElementById(containerId);
        if (!container) return; // safety check — do nothing if the container doesn't exist yet

        // Build the header row (the column titles)
        let headerHTML = '<div class="grid gap-2 text-gray-500 text-xs border-b border-gray-800 pb-1 mb-1" style="grid-template-columns: repeat(' + columns.length + ', 1fr);">';
        for (let i = 0; i < columns.length; i++) {
            headerHTML += '<span class="truncate">' + columns[i].label + '</span>';
        }
        headerHTML += '</div>';

        // Build each data row
        let rowsHTML = '';
        for (let r = 0; r < rows.length; r++) {
            const row = rows[r];
            rowsHTML += '<div class="grid gap-2 text-xs py-1 border-b border-gray-900 hover:bg-gray-900" style="grid-template-columns: repeat(' + columns.length + ', 1fr);">';

            for (let c = 0; c < columns.length; c++) {
                const key = columns[c].key;
                const value = row[key] !== undefined ? row[key] : '—'; // fallback if data is missing
                rowsHTML += '<span class="truncate text-gray-400" title="' + value + '">' + value + '</span>';
            }

            rowsHTML += '</div>';
        }

        container.innerHTML = headerHTML + rowsHTML;
    }

    // ── Generic feed panel loader ──────────────────────────────
    // containerId: where to render this panel
    // feedSource: which feed_source value to filter for (e.g. "URLHaus", "OpenPhish", "FeodoTracker")
    async function loadFeedPanel(containerId, feedSource) {
        try {
            const res = await fetch('/api/threats/json?source=' + feedSource);
            const data = await res.json();

            const rows = data.recent.map(function(t) {
                return {
                    indicator: t.indicator,
                    type: t.threat_type,
                    seen: formatAge(t.seen_at)
                };
            });

            renderPanel(containerId, [
                { label: "INDICATOR", key: "indicator" },
                { label: "TYPE",      key: "type" },
                { label: "SEEN",      key: "seen" }
            ], rows);

        } catch (e) {
            console.error('Failed to load panel for ' + feedSource + ':', e);
        }
    }

    // Converts a timestamp like "2024-06-18T10:30:00Z" into "2h ago" style text
    function formatAge(isoString) {
        const seenDate = new Date(isoString);
        const now = new Date();
        const diffMs = now - seenDate; // subtracting two Dates gives milliseconds
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return "now";
        if (diffMins < 60) return diffMins + "m";
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return diffHours + "h";
        const diffDays = Math.floor(diffHours / 24);
        return diffDays + "d";
    }

    loadFeedPanel('panel-malware', 'URLHaus');
loadFeedPanel('panel-phishing', 'OpenPhish');
loadFeedPanel('panel-botnet', 'FeodoTracker');
loadFeedPanel('panel-threatfox', 'ThreatFox');

setInterval(function() {
    loadFeedPanel('panel-malware', 'URLHaus');
    loadFeedPanel('panel-phishing', 'OpenPhish');
    loadFeedPanel('panel-botnet', 'FeodoTracker');
    loadFeedPanel('panel-threatfox', 'ThreatFox');
}, 10000);

    // ── Deterministic color generator ────────────────────────
    // Turns any string into a consistent, repeatable color.
    // Same input string -> always the exact same color, forever.
    function stringToColor(str) {
        let hash = 0;
        // Walk through every character in the string and build up a number
        // charCodeAt() gives the numeric code behind a character (like 'A' = 65)
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
            // << is a "bit shift" operator — this is just a fast way to
            // multiply and mix the number around so similar strings don't
            // accidentally produce similar colors
        }
        // Force the hash into a 0-360 range (the full color wheel in HSL format)
        const hue = Math.abs(hash) % 360;

        // HSL = Hue, Saturation, Lightness. We fix saturation/lightness so
        // every color stays vivid and visible against our dark background,
        // only the HUE (the actual color) changes per location.
        return 'hsl(' + hue + ', 80%, 60%)';
    }

    // ── Globe Setup ───────────────────────────────────────────
    // We only want to CREATE the globe object once. If we created
    // a brand new globe every time we refresh data, we'd get
    // duplicate spinning globes stacked on top of each other.
    // So we declare this variable OUTSIDE any function, and only
    // build it the very first time.
    let myGlobe = null;

    function initGlobe() {
        const container = document.getElementById('globe-container');

        // Globe() is the function globe.gl gives us. We chain methods onto it
        // (this is called "method chaining" — each .something() returns the
        // globe itself again, so you can keep calling more methods in a row,
        // similar to how jQuery or some JS libraries work)
        myGlobe = Globe()
            (container) // this tells globe.gl WHERE on the page to render

            // Use a free, public dark-themed earth texture image
            .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
            .backgroundColor('rgba(0,0,0,0)') // transparent background, blends with our dark page

            // Points configuration — glowing dots instead of arcs
            .pointAltitude(0.01)   // how far the dot floats above the surface
            .pointRadius(0.4)      // size of each glowing dot
            .pointColor('color')   // tells globe.gl: "read the color from each point's .color field"
            .pointLabel('label')   // shows a text tooltip on hover
            .pointsMerge(false);

        // Auto-rotate the globe slowly, just like the reel screenshot
        myGlobe.controls().autoRotate = true;
        myGlobe.controls().autoRotateSpeed = 0.5;

        // Resize the globe to fit its container nicely
        myGlobe.width(container.offsetWidth);
        myGlobe.height(320);
    }

    async function loadGlobePoints() {
        try {
            const res = await fetch('/api/arcs');
            const points = await res.json();

            // Attach a unique color + label to every point before handing it to globe.gl
            points.forEach(function(p) {
                const key = p.city + ',' + p.country;
                p.color = stringToColor(key);
                p.lat = p.startLat;  // globe.gl's pointsData wants "lat"/"lng", not "startLat"
                p.lng = p.startLng;
                p.label = p.city + ', ' + p.country + ' (' + p.count + ' threats)';
            });

            myGlobe.pointsData(points);

            // Reuse the same color logic to draw the matching legend below
            renderGeoLegend(points);

        } catch (e) {
            console.error('Failed to load globe points:', e);
        }
    }

    // ── Color-coded legend, matches the globe dots exactly ───
    function renderGeoLegend(points) {
        const legend = document.getElementById('geo-legend');
        if (!legend) return;

        // Sort by count descending, so the most active threat locations show first
        // .slice() makes a copy first so we don't scramble the original array order
        const sorted = points.slice().sort(function(a, b) { return b.count - a.count; });

        legend.innerHTML = sorted.map(function(p) {
            return '<span class="flex items-center gap-1 px-2 py-0.5 rounded" style="background: rgba(255,255,255,0.05);">'
                 + '<span style="width:8px; height:8px; border-radius:50%; background:' + p.color + '; display:inline-block;"></span>'
                 + '<span class="text-gray-400">' + p.city + ', ' + p.country + ' (' + p.count + ')</span>'
                 + '</span>';
        }).join('');
    }

    initGlobe();
    loadGlobePoints();
    setInterval(loadGlobePoints, 30000); // refresh every 30 seconds — locations don't change as fast as the table
    // ── Widget: Crypto Prices ──────────────────────────────────
async function loadCryptoPrices() {
    try {
        const res = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd&include_24hr_change=true');
        const data = await res.json();

        const container = document.getElementById('crypto-prices');

        // data looks like: { bitcoin: { usd: 61204, usd_24h_change: 2.46 }, ethereum: {...} }
        const btcChange = data.bitcoin.usd_24h_change;
        const ethChange = data.ethereum.usd_24h_change;

        // Pick green or red text depending on whether price went up or down today
        const btcColor = btcChange >= 0 ? 'text-green-400' : 'text-red-400';
        const ethColor = ethChange >= 0 ? 'text-green-400' : 'text-red-400';

        container.innerHTML =
            '<div class="mb-2">BTC · USD<br>'
            + '<span class="text-lg text-gray-200">$' + Math.round(data.bitcoin.usd).toLocaleString() + '</span> '
            + '<span class="' + btcColor + '">' + btcChange.toFixed(2) + '%</span></div>'
            + '<div>ETH · USD<br>'
            + '<span class="text-lg text-gray-200">$' + Math.round(data.ethereum.usd).toLocaleString() + '</span> '
            + '<span class="' + ethColor + '">' + ethChange.toFixed(2) + '%</span></div>';

    } catch (e) {
        console.error('Failed to load crypto prices:', e);
    }
}

loadCryptoPrices();
setInterval(loadCryptoPrices, 60000); // prices don't need to update faster than once a minute


// ── Widget: ISS Position ───────────────────────────────────
async function loadISSPosition() {
    try {
        const res = await fetch('https://api.open-notify.org/iss-now.json');
        const data = await res.json();

        const lat = parseFloat(data.iss_position.latitude).toFixed(2);
        const lng = parseFloat(data.iss_position.longitude).toFixed(2);

        // Convert the Unix timestamp (seconds since 1970) into a readable time
        const timestamp = new Date(data.timestamp * 1000);

        document.getElementById('iss-position').innerHTML =
            'LAT, LNG<br>'
            + '<span class="text-gray-200">' + lat + '°, ' + lng + '°</span><br>'
            + '<span class="text-gray-600">as of ' + timestamp.toLocaleTimeString() + '</span>';

    } catch (e) {
        console.error('Failed to load ISS position:', e);
    }
}

loadISSPosition();
setInterval(loadISSPosition, 5000); // the ISS moves fast — refresh every 5 seconds


// ── Widget: Recent Earthquakes ─────────────────────────────
async function loadEarthquakes() {
    try {
        // This USGS endpoint returns earthquakes from the last hour, magnitude 2.5+
        const res = await fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_hour.geojson');
        const data = await res.json();

        const container = document.getElementById('quake-list');

        if (data.features.length === 0) {
            container.innerHTML = '<span class="text-gray-600">No recent quakes ≥ 2.5</span>';
            return;
        }

        // Each "feature" is one earthquake. properties.mag = magnitude,
        // properties.place = human-readable location, geometry.coordinates = [lng, lat, depth]
        container.innerHTML = data.features.slice(0, 5).map(function(quake) {
            const mag = quake.properties.mag.toFixed(1);
            const place = quake.properties.place;
            const magColor = quake.properties.mag >= 5 ? 'text-red-400' : 'text-yellow-500';

            return '<div class="mb-1 pb-1 border-b border-gray-900">'
                 + '<span class="' + magColor + '">M' + mag + '</span> '
                 + '<span class="text-gray-400">' + place + '</span>'
                 + '</div>';
        }).join('');

    } catch (e) {
        console.error('Failed to load earthquake data:', e);
    }
}

loadEarthquakes();
setInterval(loadEarthquakes, 60000); // earthquakes are infrequent, no need to poll fast


</script>

</body>
</html>`
