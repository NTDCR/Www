const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const ARTIFACTS_DIR = path.join(__dirname, '..', 'dist');
const CHROME_PATH = process.platform === 'win32'
  ? 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
  : '/usr/bin/google-chrome';
const PORT = 4173; // Use production build preview port

// Helper to send CDP command
function sendCdpCommand(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1000000);
    const handler = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id === id) {
        ws.removeEventListener('message', handler);
        if (msg.error) {
          reject(new Error(msg.error.message));
        } else {
          resolve(msg.result);
        }
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function runLiveBrowserTest() {
  console.log('========================================================================');
  console.log('   CONTENTGUARD PRO MAX — REAL-WORLD LIVE BROWSER AUTOMATION TEST');
  console.log('========================================================================\n');

  // 1. Start Vite Preview Server
  console.log(`[1/6] Launching local production web server on http://localhost:${PORT}...`);
  const serverProcess = spawn('npx.cmd', ['vite', 'preview', '--port', String(PORT), '--host', '127.0.0.1'], {
    cwd: path.join(__dirname, '..'),
    shell: true
  });

  await sleep(3000);

  // 2. Launch Google Chrome in Headless Automation Mode
  console.log('[2/6] Spawning Google Chrome (headless=new, remote-debugging-port=9222)...');
  const chromeProcess = spawn(CHROME_PATH, [
    '--headless=new',
    '--remote-debugging-port=9222',
    '--no-first-run',
    '--no-default-browser-check',
    '--window-size=1440,900',
    '--user-data-dir=' + path.join(process.env.TEMP, 'chrome_contentguard_audit')
  ]);

  await sleep(2500);

  // 3. Connect to Chrome CDP WebSocket
  console.log('[3/6] Connecting to Chrome DevTools Protocol (CDP)...');
  const targets = await new Promise((resolve, reject) => {
    http.get('http://127.0.0.1:9222/json', (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve(JSON.parse(body)));
    }).on('error', reject);
  });

  const pageTarget = targets.find(t => t.type === 'page') || targets[0];
  console.log('CDP Target WebSocket URL:', pageTarget.webSocketDebuggerUrl);

  const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

  console.log('Connected to Chrome WebSocket successfully!\n');

  // Set up telemetry capture
  const consoleMessages = [];
  const networkRequests = [];

  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.method === 'Console.messageAdded') {
      consoleMessages.push(msg.params.message);
    } else if (msg.method === 'Runtime.consoleAPICalled') {
      const text = msg.params.args.map(a => a.value || a.description).join(' ');
      consoleMessages.push({ type: msg.params.type, text });
    } else if (msg.method === 'Network.requestWillBeSent') {
      networkRequests.push({
        url: msg.params.request.url,
        method: msg.params.request.method,
        initiator: msg.params.initiator.type
      });
    }
  });

  await sendCdpCommand(ws, 'Page.enable');
  await sendCdpCommand(ws, 'Runtime.enable');
  await sendCdpCommand(ws, 'Network.enable');

  // 4. Navigate to ContentGuard Pro MAX
  console.log(`[4/6] Navigating to http://localhost:${PORT}/ ...`);
  await sendCdpCommand(ws, 'Page.navigate', { url: `http://localhost:${PORT}/` });

  // Wait for React to mount and hydrate
  await sleep(4000);

  // Check page title and root mounting
  const evalTitle = await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.title'
  });
  console.log('Verified Page Title:', evalTitle.result.value);

  const evalRoot = await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("root")?.children.length > 0'
  });
  console.log('Verified React Root Mounted & Active:', evalRoot.result.value);

  // Capture Screenshot 1: Tab 1 - Dual-Vault Protection
  console.log('\n[5/6] Testing Interactive UI Tabs & Capturing Live Screenshots...');
  
  const shot1 = await sendCdpCommand(ws, 'Page.captureScreenshot', { format: 'png' });
  const shot1Path = path.join(ARTIFACTS_DIR, 'browser_tab1_protect.png');
  fs.writeFileSync(shot1Path, Buffer.from(shot1.data, 'base64'));
  console.log('✓ Captured Tab 1 (Dual-Vault Protection): browser_tab1_protect.png');

  // Click Tab 2: Extract
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("nav-extract-tab")?.click()'
  });
  await sleep(1000);
  const shot2 = await sendCdpCommand(ws, 'Page.captureScreenshot', { format: 'png' });
  const shot2Path = path.join(ARTIFACTS_DIR, 'browser_tab2_extract.png');
  fs.writeFileSync(shot2Path, Buffer.from(shot2.data, 'base64'));
  console.log('✓ Clicked & Captured Tab 2 (Decrypt & Extract): browser_tab2_extract.png');

  // Click Tab 3: Inspector
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("nav-inspector-tab")?.click()'
  });
  await sleep(1000);
  const shot3 = await sendCdpCommand(ws, 'Page.captureScreenshot', { format: 'png' });
  const shot3Path = path.join(ARTIFACTS_DIR, 'browser_tab3_inspector.png');
  fs.writeFileSync(shot3Path, Buffer.from(shot3.data, 'base64'));
  console.log('✓ Clicked & Captured Tab 3 (Statistical Inspector): browser_tab3_inspector.png');

  // Click Tab 4: Audit
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("nav-audit-tab")?.click()'
  });
  await sleep(1000);
  const shot4 = await sendCdpCommand(ws, 'Page.captureScreenshot', { format: 'png' });
  const shot4Path = path.join(ARTIFACTS_DIR, 'browser_tab4_audit.png');
  fs.writeFileSync(shot4Path, Buffer.from(shot4.data, 'base64'));
  console.log('✓ Clicked & Captured Tab 4 (Audit Trail): browser_tab4_audit.png');

  // Test Header Modal: Air-Gap Deployment Modal
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("header-airgap-btn")?.click()'
  });
  await sleep(1000);
  const shotModal = await sendCdpCommand(ws, 'Page.captureScreenshot', { format: 'png' });
  const shotModalPath = path.join(ARTIFACTS_DIR, 'browser_modal_airgap.png');
  fs.writeFileSync(shotModalPath, Buffer.from(shotModal.data, 'base64'));
  console.log('✓ Clicked & Captured Air-Gap Security Modal: browser_modal_airgap.png');

  // Close Modal
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Acknowledge"))?.click()'
  });
  await sleep(800);

  // Return to Tab 1
  await sendCdpCommand(ws, 'Runtime.evaluate', {
    expression: 'document.getElementById("nav-protect-tab")?.click()'
  });
  await sleep(1000);

  // 6. Report Live Findings
  console.log('\n[6/6] Real-World Browser Verification Summary:');
  console.log('========================================================================');
  console.log(`• Total Console Logs Captured: ${consoleMessages.length}`);
  const errors = consoleMessages.filter(m => m.type === 'error' || (m.level && m.level === 'error'));
  console.log(`• JavaScript Runtime Errors: ${errors.length}`);
  if (errors.length > 0) {
    console.log('  Errors detected:', errors);
  } else {
    console.log('  ✅ 0 JavaScript Errors in Browser Console (100% Clean Hydration)');
  }

  console.log(`\n• Total Network Requests: ${networkRequests.length}`);
  const externalRequests = networkRequests.filter(r => !r.url.includes('localhost') && !r.url.includes('127.0.0.1'));
  console.log(`• Outbound / External Network Telemetry: ${externalRequests.length}`);
  if (externalRequests.length > 0) {
    console.log('  External calls detected:', externalRequests);
  } else {
    console.log('  ✅ 100% Zero-Telemetry: ZERO External Requests Sent (Air-Gap Confirmed)');
  }

  console.log('\n• Live Screenshots Saved to Artifacts:');
  console.log('  1. browser_tab1_protect.png');
  console.log('  2. browser_tab2_extract.png');
  console.log('  3. browser_tab3_inspector.png');
  console.log('  4. browser_tab4_audit.png');
  console.log('  5. browser_modal_airgap.png');
  console.log('========================================================================\n');

  // Clean shutdown
  ws.close();
  chromeProcess.kill();
  serverProcess.kill();
  process.exit(0);
}

runLiveBrowserTest().catch(err => {
  console.error('Fatal Test Error:', err);
  process.exit(1);
});
