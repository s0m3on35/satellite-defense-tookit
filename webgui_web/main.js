// Onboarding transition
window.addEventListener("load", () => {
  const onboarding = document.getElementById("onboarding");
  const skipBtn = document.getElementById("skipOnboarding");

  if (onboarding) {
    skipBtn.addEventListener("click", () => {
      onboarding.style.opacity = 0;
      setTimeout(() => onboarding.style.display = "none", 1000);
    });

    setTimeout(() => {
      onboarding.style.opacity = 0;
      setTimeout(() => onboarding.style.display = "none", 1000);
    }, 6000);
  }

  initializeApp();
});

// Global state
let modules = [];
let chain = [];
let socket;

function initializeApp() {
  fetchModules();
  fetchAgents();
  initWebSocket();
  setupDragAndDrop();
}

function fetchModules() {
  fetch("/api/modules")
    .then(res => res.json())
    .then(data => {
      modules = data;
      renderModules(data);
      populateCategories(data);
    })
    .catch(err => console.error("Module fetch failed:", err));
}

function fetchAgents() {
  fetch("/api/agents")
    .then(res => res.json())
    .then(data => {
      const agentSelector = document.getElementById("agentSelector");
      data.forEach(agent => {
        const option = document.createElement("option");
        option.value = agent.id || agent.name || "default";
        option.textContent = agent.name || agent.id;
        agentSelector.appendChild(option);
      });
    });
}

function renderModules(modList) {
  const container = document.getElementById("moduleList");
  container.innerHTML = "";

  modList.forEach(mod => {
    const item = document.createElement("li");
    item.className = "module-item";
    item.textContent = mod.name;
    item.dataset.file = mod.file;
    item.dataset.category = mod.category;

    item.setAttribute("draggable", "true");
    item.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", JSON.stringify(mod));
    });

    container.appendChild(item);
  });
}

function populateCategories(modList) {
  const filter = document.getElementById("categoryFilter");
  const categories = Array.from(new Set(modList.map(m => m.category)));
  categories.sort();
  categories.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    filter.appendChild(opt);
  });

  filter.addEventListener("change", () => {
    const selected = filter.value;
    if (selected === "All") {
      renderModules(modules);
    } else {
      renderModules(modules.filter(m => m.category === selected));
    }
  });
}

function setupDragAndDrop() {
  const dropZone = document.getElementById("chainList");
  dropZone.addEventListener("dragover", e => e.preventDefault());
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    const mod = JSON.parse(e.dataTransfer.getData("text/plain"));
    chain.push(mod);
    renderChain();
  });
}

function renderChain() {
  const container = document.getElementById("chainList");
  container.innerHTML = "";

  chain.forEach((mod, idx) => {
    const item = document.createElement("li");
    item.className = "chain-item";
    item.textContent = `${idx + 1}. ${mod.name}`;
    item.dataset.file = mod.file;

    const removeBtn = document.createElement("button");
    removeBtn.textContent = "×";
    removeBtn.onclick = () => {
      chain.splice(idx, 1);
      renderChain();
    };

    item.appendChild(removeBtn);
    container.appendChild(item);
  });
}

function initWebSocket() {
  socket = new WebSocket("ws://localhost:5000/socket.io/?EIO=4&transport=websocket");

  socket.onmessage = (event) => {
    const payload = event.data;
    if (payload.includes("console_output")) {
      const parsed = parseWebSocketPayload(payload);
      if (parsed && parsed.line) {
        logToConsole(parsed.line);
      }
    }
  };

  socket.onopen = () => logToConsole("[WebSocket] Connected.");
  socket.onerror = err => logToConsole("[WebSocket Error] " + err.message);
}

function parseWebSocketPayload(payload) {
  try {
    const parts = payload.split("42")[1];
    if (parts) {
      const [, data] = JSON.parse(parts);
      return data;
    }
  } catch (e) {
    return null;
  }
}

function logToConsole(line) {
  const output = document.getElementById("consoleOutput");
  output.textContent += line + "\n";
  output.scrollTop = output.scrollHeight;
}

function runChain() {
  if (!chain.length) {
    logToConsole("[!] Execution chain is empty.");
    return;
  }

  document.getElementById("progressBar").value = 0;

  fetch("/api/chain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain })
  })
    .then(res => res.json())
    .then(() => {
      logToConsole("[*] Chain execution started.");
    });
}

function clearChain() {
  chain = [];
  renderChain();
  logToConsole("[*] Chain cleared.");
}

function exportChain() {
  const blob = new Blob([JSON.stringify(chain, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "execution_chain.json";
  a.click();
  URL.revokeObjectURL(url);
}

// Module search
document.getElementById("searchBox").addEventListener("input", (e) => {
  const term = e.target.value.toLowerCase();
  renderModules(modules.filter(m => m.name.toLowerCase().includes(term)));
});
