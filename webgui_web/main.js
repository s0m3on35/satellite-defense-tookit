// === Onboarding Transition ===
window.addEventListener("load", () => {
  const onboarding = document.getElementById("onboarding");
  const mainUI = document.getElementById("mainUI");
  const skipBtn = document.getElementById("skipButton");

  const showMainUI = () => {
    onboarding.style.opacity = 0;
    setTimeout(() => {
      onboarding.style.display = "none";
      mainUI.classList.remove("hidden");
    }, 1000);
  };

  setTimeout(showMainUI, 5000); // auto-transition
  skipBtn.addEventListener("click", showMainUI);
});

// === Real-time Fetching & Execution Logic ===
const moduleListEl = document.getElementById("moduleList");
const chainListEl = document.getElementById("chainList");
const consoleEl = document.getElementById("consoleOutput");
const agentSelector = document.getElementById("agentSelector");
const categoryFilter = document.getElementById("categoryFilter");
const searchBox = document.getElementById("searchBox");

let allModules = [];

// === WebSocket Console Stream ===
const socket = new WebSocket("ws://localhost:5000/socket.io/?EIO=4&transport=websocket");

socket.onmessage = (event) => {
  const data = event.data;
  if (data.includes("console_output")) {
    const payloadMatch = data.match(/"line":"(.*?)"}/);
    if (payloadMatch) {
      const line = payloadMatch[1].replace(/\\"/g, '"');
      consoleEl.textContent += line + "\n";
      consoleEl.scrollTop = consoleEl.scrollHeight;
    }
  }
};

// === Load Agents ===
async function loadAgents() {
  const res = await fetch("/api/agents");
  const agents = await res.json();
  agentSelector.innerHTML = "";
  agents.forEach(agent => {
    const opt = document.createElement("option");
    opt.value = agent.id;
    opt.textContent = agent.name;
    agentSelector.appendChild(opt);
  });
}

// === Load Modules ===
async function loadModules() {
  const res = await fetch("/api/modules");
  const modules = await res.json();
  allModules = modules;
  populateModuleList(modules);
  populateCategoryFilter(modules);
}

function populateModuleList(modules) {
  moduleListEl.innerHTML = "";
  modules.forEach(mod => {
    const item = document.createElement("li");
    item.textContent = mod.name;
    item.draggable = true;
    item.classList.add("module-item");
    item.dataset.file = mod.file;
    item.dataset.category = mod.category;
    item.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", JSON.stringify(mod));
    });
    moduleListEl.appendChild(item);
  });
}

function populateCategoryFilter(modules) {
  const categories = new Set(modules.map(m => m.category));
  categoryFilter.innerHTML = `<option value="All">All</option>`;
  categories.forEach(cat => {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });
}

categoryFilter.addEventListener("change", () => {
  const selected = categoryFilter.value;
  const filtered = selected === "All" ? allModules : allModules.filter(m => m.category === selected);
  populateModuleList(filtered);
});

searchBox.addEventListener("input", () => {
  const text = searchBox.value.toLowerCase();
  const filtered = allModules.filter(m => m.name.toLowerCase().includes(text));
  populateModuleList(filtered);
});

// === Chain Actions ===
chainListEl.addEventListener("dragover", e => e.preventDefault());
chainListEl.addEventListener("drop", e => {
  e.preventDefault();
  const mod = JSON.parse(e.dataTransfer.getData("text/plain"));
  const item = document.createElement("li");
  item.textContent = mod.name;
  item.dataset.file = mod.file;
  chainListEl.appendChild(item);
});

function runChain() {
  const chain = [...chainListEl.children].map(el => ({
    name: el.textContent,
    file: el.dataset.file
  }));
  fetch("/api/chain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chain })
  });
}

function clearChain() {
  chainListEl.innerHTML = "";
}

function exportChain() {
  const chain = [...chainListEl.children].map(el => ({
    name: el.textContent,
    file: el.dataset.file
  }));
  const blob = new Blob([JSON.stringify(chain, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "module_chain.json";
  link.click();
}

// === Init ===
loadModules();
loadAgents();
