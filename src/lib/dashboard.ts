/**
 * Dashboard HTML Template — Extracted from index.ts for testability
 *
 * Generates the AgentShield security dashboard with optional CSP nonce.
 */

export function getDashboardHtml(nonce?: string): string {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield Dashboard</title>
  <script src="https://cdn.tailwindcss.com"${nonceAttr}></script>
  <style${nonceAttr}>
    @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    .pulse-dot { animation: pulse-dot 2s ease-in-out infinite; }
  </style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-6xl mx-auto px-4 py-8">
    <header class="flex items-center justify-between mb-8">
      <div class="flex items-center gap-3">
        <div class="w-3 h-3 bg-green-500 rounded-full pulse-dot" id="status-dot"></div>
        <h1 class="text-2xl font-bold tracking-tight">AgentShield</h1>
        <span class="text-sm text-gray-500">Security Dashboard</span>
      </div>
      <span class="text-xs text-gray-600" id="uptime">Connected</span>
    </header>

    <div class="grid grid-cols-4 gap-4 mb-8" id="stats">
      <div class="bg-gray-900 rounded-lg p-4 border border-gray-800">
        <div class="text-xs text-gray-500 uppercase tracking-wider">Scanned</div>
        <div class="text-3xl font-mono font-bold mt-1" id="stat-total">0</div>
      </div>
      <div class="bg-gray-900 rounded-lg p-4 border border-red-900/30">
        <div class="text-xs text-red-400 uppercase tracking-wider">Blocked</div>
        <div class="text-3xl font-mono font-bold text-red-400 mt-1" id="stat-blocked">0</div>
      </div>
      <div class="bg-gray-900 rounded-lg p-4 border border-yellow-900/30">
        <div class="text-xs text-yellow-400 uppercase tracking-wider">Warned</div>
        <div class="text-3xl font-mono font-bold text-yellow-400 mt-1" id="stat-warned">0</div>
      </div>
      <div class="bg-gray-900 rounded-lg p-4 border border-green-900/30">
        <div class="text-xs text-green-400 uppercase tracking-wider">Allowed</div>
        <div class="text-3xl font-mono font-bold text-green-400 mt-1" id="stat-allowed">0</div>
      </div>
    </div>

    <div class="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
      <div class="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
        <h2 class="font-semibold text-sm">Live Events</h2>
        <span class="text-xs text-gray-500" id="event-count">0 events</span>
      </div>
      <div class="divide-y divide-gray-800/50 max-h-[60vh] overflow-y-auto" id="events">
        <div class="p-4 text-center text-gray-600 text-sm">Waiting for events...</div>
      </div>
    </div>
  </div>

  <script${nonceAttr}>
    const severityColors = {
      critical: 'text-red-400 bg-red-950',
      high: 'text-orange-400 bg-orange-950',
      medium: 'text-yellow-400 bg-yellow-950',
      low: 'text-blue-400 bg-blue-950',
      none: 'text-gray-400 bg-gray-800'
    };
    const outcomeIcons = { blocked: '\\u26d4', warned: '\\u26a0\\ufe0f', allowed: '\\u2705' };

    let eventCount = 0;
    const eventsEl = document.getElementById('events');
    const eventCountEl = document.getElementById('event-count');

    function updateStats(stats) {
      document.getElementById('stat-total').textContent = stats.totalScanned;
      document.getElementById('stat-blocked').textContent = stats.blocked;
      document.getElementById('stat-warned').textContent = stats.warned;
      document.getElementById('stat-allowed').textContent = stats.allowed;
    }

    function addEvent(entry) {
      if (eventCount === 0) eventsEl.innerHTML = '';
      eventCount++;
      eventCountEl.textContent = eventCount + ' events';

      const colors = severityColors[entry.severity] || severityColors.none;
      const icon = outcomeIcons[entry.outcome] || '';
      const time = new Date(entry.timestamp).toLocaleTimeString();

      const div = document.createElement('div');
      div.className = 'px-4 py-3 flex items-start gap-3 hover:bg-gray-800/50 transition-colors';

      const iconSpan = document.createElement('span');
      iconSpan.className = 'text-lg';
      iconSpan.textContent = icon;
      div.appendChild(iconSpan);

      const info = document.createElement('div');
      info.className = 'flex-1 min-w-0';

      const row = document.createElement('div');
      row.className = 'flex items-center gap-2';

      const timeSpan = document.createElement('span');
      timeSpan.className = 'text-xs font-mono text-gray-500';
      timeSpan.textContent = time;
      row.appendChild(timeSpan);

      const sevSpan = document.createElement('span');
      sevSpan.className = 'text-xs px-1.5 py-0.5 rounded font-mono ' + colors;
      sevSpan.textContent = entry.severity.toUpperCase();
      row.appendChild(sevSpan);

      const hookSpan = document.createElement('span');
      hookSpan.className = 'text-xs text-gray-500';
      hookSpan.textContent = entry.hook;
      row.appendChild(hookSpan);

      if (entry.toolName) {
        const toolSpan = document.createElement('span');
        toolSpan.className = 'text-xs text-gray-600';
        toolSpan.textContent = '(' + entry.toolName + ')';
        row.appendChild(toolSpan);
      }

      info.appendChild(row);

      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'text-sm text-gray-300 mt-1 truncate';
      detailsDiv.textContent = entry.details;
      info.appendChild(detailsDiv);

      if (entry.patterns.length > 0) {
        const patternsDiv = document.createElement('div');
        patternsDiv.className = 'text-xs text-gray-500 mt-1 font-mono truncate';
        patternsDiv.textContent = entry.patterns.join(', ');
        info.appendChild(patternsDiv);
      }

      div.appendChild(info);

      eventsEl.insertBefore(div, eventsEl.firstChild);
    }

    const MAX_DOM_EVENTS = 100;

    // SSE Connection
    const es = new EventSource('/agentshield/events');
    es.onmessage = (e) => {
      let entry;
      try { entry = JSON.parse(e.data); } catch { return; }
      addEvent(entry);
      // Cap DOM events
      while (eventsEl.children.length > MAX_DOM_EVENTS) {
        eventsEl.removeChild(eventsEl.lastChild);
      }
      // Re-fetch stats
      fetch('/agentshield/api/stats').then(r => r.json()).then(updateStats).catch(() => {
        document.getElementById('uptime').textContent = 'Stats fetch failed';
      });
    };
    es.addEventListener('stats', (e) => { try { updateStats(JSON.parse(e.data)); } catch { /* malformed stats */ } });
    es.onopen = () => {
      document.getElementById('status-dot').className = 'w-3 h-3 bg-green-500 rounded-full pulse-dot';
      document.getElementById('uptime').textContent = 'Connected';
    };
    es.onerror = () => {
      document.getElementById('status-dot').className = 'w-3 h-3 bg-red-500 rounded-full';
      document.getElementById('uptime').textContent = 'Disconnected — reconnecting...';
    };

    // Initial stats
    fetch('/agentshield/api/stats').then(r => r.json()).then(updateStats).catch(() => {});
  </script>
</body>
</html>`;
}
