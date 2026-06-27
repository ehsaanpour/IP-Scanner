// State management
let allResults = [];
let activeScanType = ''; // 'quick', 'custom', 'test', 'colos'
let totalIPsToScan = 0;
let testedCount = 0;
let healthyCount = 0;
let failedCount = 0;

// Presets state for Quick Scan
let quickPresets = {
  count: 5000,
  workers: 50,
  timeout: 2000
};

// Grouped Colos state
let coloGroups = {}; // coloName -> { count, totalLatency, bestLatency, healthyCount }

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
  // Load version in About screen
  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.GetVersion().then(v => {
      document.getElementById('about-version').innerText = v;
    });
  }

  // Setup Wails Event Listeners
  if (window.runtime) {
    window.runtime.EventsOn('scan:result', onScanResult);
    window.runtime.EventsOn('scan:stats', onScanStats);
    window.runtime.EventsOn('scan:done', onScanDone);
    window.runtime.EventsOn('scan:error', onScanError);
    window.runtime.EventsOn('scan:cancelled', onScanCancelled);
    window.runtime.EventsOn('test:total', onTestTotal);
  }
});

// Screen navigation
function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => {
    s.classList.remove('active');
  });
  document.getElementById(screenId).classList.add('active');
}

// Quit App
function quitApp() {
  if (window.runtime) {
    window.runtime.Quit();
  } else {
    window.close();
  }
}

// Open GitHub Link
function openGitHub() {
  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.OpenGitHub();
  }
}

// Copy results to clipboard
function copyResultsToClipboard() {
  // Take top 20 healthy IPs
  const healthy = allResults.filter(r => r.isHealthy);
  
  // Sort by avg latency
  healthy.sort((a, b) => a.avg - b.avg);
  
  const top20 = healthy.slice(0, 20);
  if (top20.length === 0) {
    alert('No healthy IPs to copy!');
    return;
  }

  const text = top20.map(r => r.ip).join('\n');

  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.CopyToClipboard(text).then(success => {
      if (success) {
        alert('Top ' + top20.length + ' healthy IPs copied to clipboard!');
      } else {
        alert('Failed to copy to clipboard.');
      }
    });
  } else {
    navigator.clipboard.writeText(text).then(() => {
      alert('Top ' + top20.length + ' healthy IPs copied to clipboard!');
    });
  }
}

// File Dialogs
function browseOutputFile() {
  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.SelectFile('Select Output File', '*.csv;*.json;*.txt', true).then(path => {
      if (path) {
        document.getElementById('custom-output').value = path;
      }
    });
  }
}

function browseInputFile() {
  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.SelectFile('Select IP List File', '*.txt;*.csv', false).then(path => {
      if (path) {
        document.getElementById('test-ips-file').value = path;
      }
    });
  }
}

// Quick Scan Presets Selection
function setPreset(type, value, element) {
  // Toggle active class on preset buttons
  const parent = element.parentElement;
  parent.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
  element.classList.add('active');

  // Handle custom input visibility
  if (type === 'quick-count') {
    const customInput = document.getElementById('quick-count-custom');
    if (value === 'custom') {
      customInput.classList.remove('hidden');
      quickPresets.count = 'custom';
    } else {
      customInput.classList.add('hidden');
      quickPresets.count = value;
    }
  } else if (type === 'quick-workers') {
    const customInput = document.getElementById('quick-workers-custom');
    if (value === 'custom') {
      customInput.classList.remove('hidden');
      quickPresets.workers = 'custom';
    } else {
      customInput.classList.add('hidden');
      quickPresets.workers = value;
    }
  } else if (type === 'quick-timeout') {
    const customContainer = document.getElementById('quick-timeout-custom-container');
    if (value === 'custom') {
      customContainer.classList.remove('hidden');
      quickPresets.timeout = 'custom';
    } else {
      customContainer.classList.add('hidden');
      quickPresets.timeout = value;
    }
  }
}

// Start Quick Scan
function startQuickScan() {
  let count = quickPresets.count;
  if (count === 'custom') {
    count = parseInt(document.getElementById('quick-count-custom').value);
  }

  let workers = quickPresets.workers;
  if (workers === 'custom') {
    workers = parseInt(document.getElementById('quick-workers-custom').value);
  }

  let timeoutMs = quickPresets.timeout;
  if (timeoutMs === 'custom') {
    timeoutMs = parseInt(document.getElementById('quick-timeout-custom').value);
  }

  if (isNaN(count) || count <= 0) {
    alert('Please enter a valid count');
    return;
  }
  if (isNaN(workers) || workers <= 0) {
    alert('Please enter a valid workers count');
    return;
  }
  if (isNaN(timeoutMs) || timeoutMs <= 0) {
    alert('Please enter a valid timeout in ms');
    return;
  }

  resetScanState('quick', count);
  document.getElementById('live-scan-title').innerText = 'Quick Scanning...';
  showScreen('screen-live-scan');

  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.StartQuickScan(count, workers, timeoutMs).then(err => {
      if (err) {
        alert(err);
        showScreen('screen-quick-scan');
      }
    });
  } else {
    // Mock for browser testing
    mockScan(count);
  }
}

// Start Custom Scan
function startCustomScan() {
  const count = parseInt(document.getElementById('custom-count').value);
  const workers = parseInt(document.getElementById('custom-workers').value);
  const timeout = document.getElementById('custom-timeout').value;
  const tries = parseInt(document.getElementById('custom-tries').value);
  const port = parseInt(document.getElementById('custom-port').value);
  const mode = document.getElementById('custom-mode').value;
  const cidr = document.getElementById('custom-cidr').value;
  const outputFile = document.getElementById('custom-output').value;
  const coloFilter = document.getElementById('custom-colo').value;
  const sni = document.getElementById('custom-sni').value;
  const useV4 = document.getElementById('custom-ipv4').checked;
  const useV6 = document.getElementById('custom-ipv6').checked;

  if (isNaN(count) || count <= 0) {
    alert('Please enter a valid count');
    return;
  }
  if (isNaN(workers) || workers <= 0) {
    alert('Please enter a valid workers count');
    return;
  }
  if (!timeout) {
    alert('Please enter a timeout');
    return;
  }
  if (isNaN(tries) || tries <= 0) {
    alert('Please enter valid tries');
    return;
  }
  if (!useV4 && !useV6) {
    alert('Please select at least one IP version (IPv4 or IPv6)');
    return;
  }

  const cfg = {
    count,
    workers,
    timeout,
    tries,
    port,
    cidr,
    outputFile,
    coloFilter,
    sni,
    mode,
    useV4,
    useV6
  };

  resetScanState('custom', count);
  document.getElementById('live-scan-title').innerText = 'Custom Scanning...';
  showScreen('screen-live-scan');

  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.StartCustomScan(cfg).then(err => {
      if (err) {
        alert(err);
        showScreen('screen-custom-scan');
      }
    });
  } else {
    mockScan(count);
  }
}

// Start Test IPs
function startTestIPs() {
  const file = document.getElementById('test-ips-file').value;
  if (!file) {
    alert('Please select an IP list file first.');
    return;
  }

  resetScanState('test', 0); // Total will be set by test:total event
  document.getElementById('live-scan-title').innerText = 'Testing IPs...';
  showScreen('screen-live-scan');

  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.StartTestIPs(file).then(err => {
      if (err) {
        alert(err);
        showScreen('screen-test-ips');
      }
    });
  } else {
    mockScan(50);
  }
}

// Start Discover Colos
function startDiscoverColos() {
  resetScanState('colos', 300);
  coloGroups = {};
  document.getElementById('colos-table-body').innerHTML = '';
  document.getElementById('colos-title').innerText = 'Discovering Colos...';
  document.getElementById('btn-cancel-colos').classList.remove('hidden');
  document.getElementById('btn-back-colos').classList.add('hidden');
  showScreen('screen-colos-results');

  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.StartDiscoverColos().then(err => {
      if (err) {
        alert(err);
        showScreen('screen-discover-colos');
      }
    });
  } else {
    mockColoDiscovery();
  }
}

// Cancel Active Scan
function cancelScan() {
  if (window.go && window.go.main && window.go.main.App) {
    window.go.main.App.CancelScan();
  } else {
    onScanCancelled();
  }
}

// Reset scan state
function resetScanState(type, total) {
  activeScanType = type;
  totalIPsToScan = total;
  allResults = [];
  testedCount = 0;
  healthyCount = 0;
  failedCount = 0;

  // Reset live stats bar
  document.getElementById('stat-tested').innerText = '0';
  document.getElementById('stat-healthy').innerText = '0';
  document.getElementById('stat-failed').innerText = '0';
  document.getElementById('stat-inflight').innerText = '0';

  // Reset progress bar
  document.getElementById('scan-progress-bar').style.width = '0%';
  document.getElementById('progress-percent').innerText = '0%';
  document.getElementById('progress-fraction').innerText = '0 / ' + total;

  // Clear live scan table
  document.getElementById('live-scan-table-body').innerHTML = '';

  // Toggle button visibility
  document.getElementById('btn-cancel-scan').classList.remove('hidden');
  document.getElementById('btn-view-results').classList.add('hidden');

  // Reset Colo Discovery stats
  document.getElementById('colo-stat-tested').innerText = '0';
  document.getElementById('colo-stat-healthy').innerText = '0';
  document.getElementById('colo-stat-inflight').innerText = '0';
}

// Event Handlers
function onTestTotal(total) {
  totalIPsToScan = total;
  document.getElementById('progress-fraction').innerText = '0 / ' + total;
}

function onScanStats(stats) {
  testedCount = stats.tested;
  healthyCount = stats.healthy;
  failedCount = stats.failed;

  if (activeScanType === 'colos') {
    document.getElementById('colo-stat-tested').innerText = stats.tested;
    document.getElementById('colo-stat-healthy').innerText = stats.healthy;
    document.getElementById('colo-stat-inflight').innerText = stats.inFlight;
  } else {
    document.getElementById('stat-tested').innerText = stats.tested;
    document.getElementById('stat-healthy').innerText = stats.healthy;
    document.getElementById('stat-failed').innerText = stats.failed;
    document.getElementById('stat-inflight').innerText = stats.inFlight;

    // Update progress bar
    if (totalIPsToScan > 0) {
      const pct = Math.min(100, Math.floor((stats.tested / totalIPsToScan) * 100));
      document.getElementById('scan-progress-bar').style.width = pct + '%';
      document.getElementById('progress-percent').innerText = pct + '%';
      document.getElementById('progress-fraction').innerText = stats.tested + ' / ' + totalIPsToScan;
    }
  }
}

function onScanResult(result) {
  if (activeScanType === 'colos') {
    // Process colo discovery result
    processColoResult(result);
  } else {
    allResults.push(result);
    appendLiveResultRow(result);
  }
}

function onScanDone() {
  if (activeScanType === 'colos') {
    document.getElementById('colos-title').innerText = 'Colo Discovery Done';
    document.getElementById('btn-cancel-colos').classList.add('hidden');
    document.getElementById('btn-back-colos').classList.remove('hidden');
  } else {
    document.getElementById('live-scan-title').innerText = 'Scan Complete';
    document.getElementById('btn-cancel-scan').classList.add('hidden');
    document.getElementById('btn-view-results').classList.remove('hidden');
  }
}

function onScanError(err) {
  alert('Scan Error: ' + err);
}

function onScanCancelled() {
  if (activeScanType === 'colos') {
    document.getElementById('colos-title').innerText = 'Discovery Cancelled';
    document.getElementById('btn-cancel-colos').classList.add('hidden');
    document.getElementById('btn-back-colos').classList.remove('hidden');
  } else {
    document.getElementById('live-scan-title').innerText = 'Scan Cancelled';
    document.getElementById('btn-cancel-scan').classList.add('hidden');
    document.getElementById('btn-view-results').classList.remove('hidden');
  }
}

// Append Row to Live Scan Table
function appendLiveResultRow(r) {
  const tbody = document.getElementById('live-scan-table-body');
  const tr = document.createElement('tr');
  
  // Highlighting
  if (r.isHealthy) {
    tr.className = 'row-healthy';
  } else if (r.loss === 100) {
    tr.className = 'row-unhealthy';
  }

  tr.innerHTML = `
    <td>${r.ip}</td>
    <td>${r.loss.toFixed(0)}%</td>
    <td>${r.avg > 0 ? r.avg.toFixed(1) : '-'}</td>
    <td>${r.min > 0 ? r.min.toFixed(1) : '-'}</td>
    <td>${r.max > 0 ? r.max.toFixed(1) : '-'}</td>
    <td>${r.jitter > 0 ? r.jitter.toFixed(1) : '-'}</td>
    <td>${r.speed > 0 ? r.speed.toFixed(1) : '-'}</td>
    <td>${r.colo || '-'}</td>
    <td>${r.tlsOk ? '<span class="text-green">✓</span>' : '<span class="text-red">✗</span>'}</td>
    <td>${r.httpStatus > 0 ? r.httpStatus : '-'}</td>
  `;

  // Insert at top of table to show newest results
  if (tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }

  // To prevent the DOM from growing infinitely and lagging, we can prune old rows if they exceed 300
  if (tbody.children.length > 300) {
    tbody.removeChild(tbody.lastChild);
  }
}

// Sort Live Results
function sortLiveResults() {
  const criteria = document.getElementById('live-sort').value;
  sortAndRenderTable('live-scan-table-body', allResults, criteria);
}

// Sort Results Screen
function sortResultsScreen() {
  const criteria = document.getElementById('results-sort').value;
  const healthy = allResults.filter(r => r.isHealthy);
  healthy.sort((a, b) => a.avg - b.avg);
  const top20 = healthy.slice(0, 20);
  sortAndRenderTable('results-table-body', top20, criteria);
}

// Sorting helper
function sortAndRenderTable(tableBodyId, resultsArray, criteria) {
  const sorted = [...resultsArray];
  
  sorted.sort((a, b) => {
    if (criteria === 'avg') {
      if (a.avg === 0) return 1;
      if (b.avg === 0) return -1;
      return a.avg - b.avg;
    } else if (criteria === 'loss') {
      return a.loss - b.loss;
    } else if (criteria === 'jitter') {
      return a.jitter - b.jitter;
    } else if (criteria === 'speed') {
      return b.speed - a.speed; // Highest speed first
    } else if (criteria === 'colo') {
      return (a.colo || '').localeCompare(b.colo || '');
    }
    return 0;
  });

  const tbody = document.getElementById(tableBodyId);
  tbody.innerHTML = '';

  sorted.forEach(r => {
    const tr = document.createElement('tr');
    if (r.isHealthy) {
      tr.className = 'row-healthy';
    } else if (r.loss === 100) {
      tr.className = 'row-unhealthy';
    }

    tr.innerHTML = `
      <td>${r.ip}</td>
      <td>${r.loss.toFixed(0)}%</td>
      <td>${r.avg > 0 ? r.avg.toFixed(1) : '-'}</td>
      <td>${r.min > 0 ? r.min.toFixed(1) : '-'}</td>
      <td>${r.max > 0 ? r.max.toFixed(1) : '-'}</td>
      <td>${r.jitter > 0 ? r.jitter.toFixed(1) : '-'}</td>
      <td>${r.speed > 0 ? r.speed.toFixed(1) : '-'}</td>
      <td>${r.colo || '-'}</td>
      <td>${r.tlsOk ? '<span class="text-green">✓</span>' : '<span class="text-red">✗</span>'}</td>
      <td>${r.httpStatus > 0 ? r.httpStatus : '-'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Show Results Screen (Top 20 Healthy sorted by avg latency)
function showResultsScreen() {
  const healthy = allResults.filter(r => r.isHealthy);
  
  // Sort by average latency
  healthy.sort((a, b) => {
    if (a.avg === 0) return 1;
    if (b.avg === 0) return -1;
    return a.avg - b.avg;
  });

  const top20 = healthy.slice(0, 20);

  const tbody = document.getElementById('results-table-body');
  tbody.innerHTML = '';

  if (top20.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">No healthy IPs found in this scan.</td></tr>`;
  } else {
    top20.forEach(r => {
      const tr = document.createElement('tr');
      tr.className = 'row-healthy';
      tr.innerHTML = `
        <td>${r.ip}</td>
        <td>${r.loss.toFixed(0)}%</td>
        <td>${r.avg.toFixed(1)}</td>
        <td>${r.min.toFixed(1)}</td>
        <td>${r.max.toFixed(1)}</td>
        <td>${r.jitter.toFixed(1)}</td>
        <td>${r.speed > 0 ? r.speed.toFixed(1) : '-'}</td>
        <td>${r.colo || '-'}</td>
        <td><span class="text-green">✓</span></td>
        <td>${r.httpStatus}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Reset results sort dropdown to default 'avg'
  document.getElementById('results-sort').value = 'avg';

  showScreen('screen-results');
}

// Process Colo Result
function processColoResult(r) {
  const colo = r.colo || 'UNKNOWN';
  if (!coloGroups[colo]) {
    coloGroups[colo] = {
      name: colo,
      totalLatency: 0,
      bestLatency: 999999,
      healthyCount: 0,
      count: 0
    };
  }

  const g = coloGroups[colo];
  g.count++;
  if (r.avg > 0) {
    g.totalLatency += r.avg;
    g.healthyCount++;
    if (r.avg < g.bestLatency) {
      g.bestLatency = r.avg;
    }
  }

  renderColosTable();
}

// Render Colos Table
function renderColosTable() {
  const tbody = document.getElementById('colos-table-body');
  tbody.innerHTML = '';

  const groups = Object.values(coloGroups);
  
  // Sort by Best Latency
  groups.sort((a, b) => {
    const aLat = a.healthyCount > 0 ? a.bestLatency : 999999;
    const bLat = b.healthyCount > 0 ? b.bestLatency : 999999;
    return aLat - bLat;
  });

  groups.forEach(g => {
    const tr = document.createElement('tr');
    if (g.healthyCount > 0) {
      tr.className = 'row-healthy';
    }

    const avgLat = g.healthyCount > 0 ? (g.totalLatency / g.healthyCount).toFixed(1) : '-';
    const bestLat = g.healthyCount > 0 ? g.bestLatency.toFixed(1) : '-';

    tr.innerHTML = `
      <td>${g.name}</td>
      <td>${avgLat} ms</td>
      <td>${bestLat} ms</td>
      <td>${g.healthyCount}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Mock functions for local browser testing
function mockScan(count) {
  console.log('Running mock scan of ' + count + ' IPs');
  let tested = 0;
  let healthy = 0;
  let failed = 0;

  const interval = setInterval(() => {
    if (tested >= count) {
      clearInterval(interval);
      onScanDone();
      return;
    }

    tested++;
    const isHealthy = Math.random() > 0.6;
    if (isHealthy) healthy++;
    else failed++;

    const res = {
      ip: `104.16.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      loss: Math.random() > 0.8 ? (Math.random() > 0.5 ? 50 : 100) : 0,
      avg: Math.random() * 150 + 20,
      min: Math.random() * 20 + 20,
      max: Math.random() * 300 + 100,
      jitter: Math.random() * 15,
      speed: isHealthy ? Math.random() * 5000 + 50 : 0,
      colo: ['FRA', 'AMS', 'DUB', 'LHR', 'CDG', 'MUC'][Math.floor(Math.random() * 6)],
      tlsOk: isHealthy,
      httpStatus: isHealthy ? 200 : (Math.random() > 0.5 ? 403 : 0),
      isHealthy: isHealthy && Math.random() > 0.2
    };

    onScanResult(res);
    onScanStats({
      tested,
      healthy,
      failed,
      inFlight: Math.floor(Math.random() * 10)
    });
  }, 50);
}

function mockColoDiscovery() {
  console.log('Running mock colo discovery');
  let tested = 0;
  let healthy = 0;

  const interval = setInterval(() => {
    if (tested >= 300) {
      clearInterval(interval);
      onScanDone();
      return;
    }

    tested++;
    const isHealthy = Math.random() > 0.7;
    if (isHealthy) healthy++;

    const res = {
      ip: `172.64.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      loss: isHealthy ? 0 : 100,
      avg: isHealthy ? Math.random() * 120 + 30 : 0,
      min: isHealthy ? Math.random() * 20 + 30 : 0,
      max: isHealthy ? Math.random() * 200 + 100 : 0,
      jitter: isHealthy ? Math.random() * 10 : 0,
      speed: 0,
      colo: ['FRA', 'AMS', 'DUB', 'LHR', 'CDG', 'MUC'][Math.floor(Math.random() * 6)],
      tlsOk: isHealthy,
      httpStatus: isHealthy ? 200 : 0,
      isHealthy: isHealthy
    };

    if (isHealthy) {
      onScanResult(res);
    }
    onScanStats({
      tested,
      healthy,
      failed: tested - healthy,
      inFlight: Math.floor(Math.random() * 15)
    });
  }, 20);
}
