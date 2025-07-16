// === Global State ===
let modules = [];
let agents = [];
let selectedAgent = null;
let chainList = [];

// === Fetch Agents and Modules ===
async function fetchAgents() {
  const res = await fetch('/api/agents');
  agents = await res.json();
  const selector = document.getElementById('agentSelector');
  agents.forEach(agent => {
    const opt = document.createElement('option');
    opt.value = agent.id || agent;
    opt.textContent = agent.id || agent;
    selector.appendChild(opt);
  });
  selector.onchange = () => selectedAgent = selector.value;
  selectedAgent = selector.value;
}

async function fetchModules() {
  const res = await fetch('/api/modules');
  modules = await res.json();
  populateModuleList();
  populateCategoryFilter();
}

// === Populate Module List ===
function populateModuleList() {
  const list = document.getElementById('moduleList');
  list.innerHTML = '';
  const category = document.getElementById('categoryFilter').value;
  const search = document.getElementById('searchBox').value.toLowerCase();

  modules
    .filter(m => (category === 'All' || m.category === category))
    .filter(m => m.name.toLowerCase().includes(search))
    .forEach(m => {
      const li = document.createElement('li');
      li.textContent = `${m.name} (${m.category})`;
      li.draggable = true;
      li.ondragstart = e => {
        e.dataTransfer.setData('text/plain', JSON.stringify(m));
      };
      list.appendChild(li);
    });
}

// === Populate Categories ===
function populateCategoryFilter() {
  const catSet = new Set(modules.map(m => m.category));
  const filter = document.getElementById('categoryFilter');
  catSet.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = c;
    filter.appendChild(opt);
  });
  filter.onchange = populateModuleList;
  document.getElementById('searchBox').oninput = populateModuleList;
}

// === Drag & Drop Chain Handling ===
const chainUl = document.getElementById('chainList');
chainUl.ondragover = e => e.preventDefault();
chainUl.ondrop = e => {
  e.preventDefault();
  const mod = JSON.parse(e.dataTransfer.getData('text/plain'));
  chainList.push(mod);
  renderChainList();
};

function renderChainList() {
  chainUl.innerHTML = '';
  chainList.forEach((m, idx) => {
    const li = document.createElement('li');
    li.textContent = `${idx + 1}. ${m.name}`;
    chainUl.appendChild(li);
  });
}

// === Execution Functions ===
async function runChain() {
  if (chainList.length === 0) return;
  const res = await fetch('/api/chain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: chainList })
  });
  logToConsole(`[+] Chain launched: ${res.status}`);
}

async function exportChain() {
  const blob = new Blob([JSON.stringify(chainList, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'execution_chain.json';
  a.click();
}

function clearChain() {
  chainList = [];
  renderChainList();
}

// === WebSocket Console Logger ===
function logToConsole(line) {
  const output = document.getElementById('consoleOutput');
  output.textContent += line + '\n';
  output.scrollTop = output.scrollHeight;
}

function initWebSocket() {
  const ws = new WebSocket("ws://localhost:5000/socket.io/?EIO=4&transport=websocket");

  ws.onopen = () => logToConsole("[WebSocket] Connected.");
  ws.onerror = err => logToConsole("[WebSocket] Error: " + err);
  ws.onmessage = msg => {
    try {
      if (msg.data.includes("console_output")) {
        const payload = JSON.parse(msg.data.split("42")[1]);
        if (payload && payload[0] === "console_output") {
          logToConsole(payload[1].line);
        }
      }
    } catch (e) {
      logToConsole("[WebSocket] Parse error: " + e);
    }
  };
}

// === Init ===
window.onload = () => {
  fetchAgents();
  fetchModules();
  initWebSocket();
};
