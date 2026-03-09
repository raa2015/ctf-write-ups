function sendMsg(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: "DICE_POPUP", ...msg }, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (resp?.error) reject(new Error(resp.error));
      else resolve(resp?.result);
    });
  });
}

let currentMnemonic = null;
let walletState = null;

async function refreshState() {
  try { walletState = await sendMsg({ action: "getState" }); } catch { walletState = null; }
  return walletState;
}

function formatBalance(hexWei) {
  const wei = BigInt(hexWei || "0x0");
  const eth = Number(wei) / 1e18;
  if (eth === 0) return "0.000000";
  return eth.toFixed(6);
}

function $(sel, root = document) { return root.querySelector(sel); }
function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

function shortAddr(addr) {
  if (!addr) return "";
  return addr.slice(0, 8) + "..." + addr.slice(-6);
}

let toastTimer;
function toast(msg, isError = false) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = msg;
  el.className = `fixed bottom-4 left-4 right-4 z-50 border-4 border-black px-4 py-3 font-bold text-sm uppercase tracking-wide shadow-neo-sm transition-all duration-200 ${isError ? "bg-neo-accent text-black" : "bg-neo-secondary text-black"}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "hidden"; }, 2500);
}

const routeTable = [];

function route(pattern, render, bind) {
  routeTable.push({ pattern, render, bind });
}

function matchRoute(hash) {
  const path = hash.split("?")[0];
  for (const r of routeTable) {
    if (r.pattern === path) return { route: r, params: {} };
  }
  return null;
}

function navigate(path) {
  window.location.hash = "#" + path;
}

function hashUrl() {
  if (location.href.includes("#")) {
    return new URL(location.href.split("#").pop(), "http://x");
  }
  return new URL("/", "http://x");
}

function currentPath() {
  return hashUrl().pathname;
}

function currentParams() {
  return Object.fromEntries(hashUrl().searchParams);
}

async function handleRoute() {
  const path = currentPath();
  const app = $("#app");
  if (!app) return;

  await refreshState();

  const effectivePath = (() => {
    const isImport = path.startsWith("/import/");
    if (!walletState?.hasWallet && path !== "/onboard" && !isImport) {
      return "/onboard";
    }
    if (walletState?.hasWallet && (path === "/" || path === "/onboard")) {
      return "/wallet";
    }
    return path;
  })();

  if (effectivePath !== path) {
    navigate(effectivePath);
    return;
  }

  const match = matchRoute(path);
  if (match) {
    app.innerHTML = "";
    const content = match.route.render(match.params);
    if (typeof content === "string") {
      app.innerHTML = content;
    } else if (content instanceof HTMLElement) {
      app.appendChild(content);
    }
    if (match.route.bind) match.route.bind(match.params);
  }
}

window.addEventListener("hashchange", handleRoute);

function btnPrimary(text, id, extraClass = "") {
  return `<button id="${id}" class="w-full h-14 border-4 border-black bg-neo-accent font-black text-sm uppercase tracking-widest shadow-neo-md cursor-pointer transition-all duration-100 active:translate-x-[3px] active:translate-y-[3px] active:shadow-neo-none hover:brightness-110 ${extraClass}">${text}</button>`;
}

function btnSecondary(text, id, extraClass = "") {
  return `<button id="${id}" class="w-full h-14 border-4 border-black bg-neo-secondary font-black text-sm uppercase tracking-widest shadow-neo-md cursor-pointer transition-all duration-100 active:translate-x-[3px] active:translate-y-[3px] active:shadow-neo-none hover:brightness-95 ${extraClass}">${text}</button>`;
}

function btnOutline(text, id, extraClass = "") {
  return `<button id="${id}" class="w-full h-14 border-4 border-black bg-neo-white font-black text-sm uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none hover:bg-neo-bg ${extraClass}">${text}</button>`;
}

function btnDanger(text, id, extraClass = "") {
  return `<button id="${id}" class="w-full h-12 border-4 border-black bg-neo-accent font-black text-xs uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none ${extraClass}">${text}</button>`;
}

function inputField(id, placeholder, type = "text", extraClass = "") {
  return `<input id="${id}" type="${type}" placeholder="${placeholder}" autocomplete="off" class="w-full h-14 px-4 border-4 border-black bg-neo-white font-bold text-base placeholder:text-black/30 focus:bg-neo-secondary focus:shadow-neo-sm focus:outline-none transition-all duration-100 ${extraClass}" />`;
}

function textareaField(id, placeholder, rows = 3) {
  return `<textarea id="${id}" rows="${rows}" placeholder="${placeholder}" autocomplete="off" class="w-full px-4 py-3 border-4 border-black bg-neo-white font-bold text-base placeholder:text-black/30 focus:bg-neo-secondary focus:shadow-neo-sm focus:outline-none transition-all duration-100 resize-none"></textarea>`;
}

function card(content, extraClass = "") {
  return `<div class="border-4 border-black bg-neo-white shadow-neo-lg p-5 ${extraClass}">${content}</div>`;
}

function label(text) {
  return `<span class="block font-black text-[11px] uppercase tracking-[0.2em] mb-1">${text}</span>`;
}

function spacer(size = "3") {
  return `<div class="h-${size}"></div>`;
}

function acctBar() {
  const acct = walletState?.accounts?.[walletState.activeIndex];
  if (!acct) return "";
  const short = acct.address.slice(0, 6) + "…" + acct.address.slice(-4);
  return `<div class="border-t-4 border-black bg-neo-bg px-4 py-2 flex items-center justify-between">
    <span class="font-black text-[10px] uppercase tracking-widest text-black/60 flex">${acct.name}</span>
    <span class="font-mono text-[11px] text-black/40">${short}</span>
  </div>`;
}

function starSvg(size = 20, cls = "") {
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="black" stroke="black" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;
}

function backBtn(label, path) {
  return `<button data-nav="${path}" class="block self-start border-4 border-black bg-neo-white px-3 py-1 font-black text-xs uppercase tracking-widest shadow-neo-sm mb-4 cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none">
    &larr; ${label}
  </button>`;
}

function bindNavButtons() {
  $$("[data-nav]").forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      navigate(el.dataset.nav);
    });
  });
}

route("/onboard", () => {
  return `
    <div class="p-5 bg-grid">
      <div class="text-center mb-6 mt-2">
        <div class="inline-block border-4 border-black bg-neo-accent shadow-neo-md px-5 py-2 -rotate-2 mb-4">
          <span class="font-black text-2xl uppercase tracking-tight">DiceWallet</span>
        </div>
        <div class="flex items-center justify-center gap-2 mt-2">
          ${starSvg(14)} ${starSvg(14)} ${starSvg(14)}
        </div>
      </div>

      <div class="flex flex-col gap-3 mt-auto">
        ${btnPrimary("Create New Wallet", "btn-generate")}
        ${btnSecondary("Import Recovery Phrase", "btn-go-import-mnemonic")}
        ${btnOutline("Import Private Key", "btn-go-import-key")}
      </div>
    </div>
  `;
}, () => {
  on("btn-generate", async () => {
    try {
      const { address, mnemonic } = await sendMsg({ action: "generate" });
      currentMnemonic = mnemonic;
      navigate("/export/phrase");
    } catch (e) { toast(e.message, true); }
  });
  on("btn-go-import-mnemonic", () => navigate("/import/mnemonic"));
  on("btn-go-import-key", () => navigate("/import/key"));
});

route("/import/mnemonic", () => {
  return `
    <div class="p-5">
      ${backBtn("BACK", walletState?.hasWallet ? "/accounts" : "/onboard")}

      <div class="border-4 border-black bg-neo-muted shadow-neo-md px-4 py-2 inline-block mb-5 -rotate-1 self-start">
        <span class="font-black text-lg uppercase tracking-tight">Import Phrase</span>
      </div>

      <div class="mb-3">
        ${label("Account Name")}
        ${inputField("import-name-input", "My Account")}
      </div>

      <div class="mb-4">
        ${label("Recovery phrase (12 or 24 words)")}
        ${textareaField("import-mnemonic-input", "abandon ability able about above absent ...", 4)}
      </div>

      <div class="mt-auto">
        ${btnPrimary("Import Wallet", "btn-import-mnemonic")}
      </div>
    </div>
  `;
}, () => {
  bindNavButtons();
  on("btn-import-mnemonic", async () => {
    const phrase = val("import-mnemonic-input");
    const name = val("import-name-input");
    if (!phrase) return toast("Enter a recovery phrase", true);
    try {
      await sendMsg({ action: "importMnemonic", mnemonic: phrase, name: name || undefined });
      toast("Wallet imported!");
      navigate("/wallet");
    } catch (e) { toast(e.message, true); }
  });
});

route("/import/key", () => {
  return `
    <div class="p-5">
      ${backBtn("BACK", walletState?.hasWallet ? "/accounts" : "/onboard")}

      <div class="border-4 border-black bg-neo-accent shadow-neo-md px-4 py-2 inline-block mb-5 rotate-1 self-start">
        <span class="font-black text-lg uppercase tracking-tight">Import Key</span>
      </div>

      <div class="mb-3">
        ${label("Account Name")}
        ${inputField("import-name-input", "My Account")}
      </div>

      <div class="mb-4">
        ${label("Private Key (hex)")}
        ${inputField("import-key-input", "0x...", "password")}
      </div>

      <div class="mt-auto">
        ${btnPrimary("Import Wallet", "btn-import-key")}
      </div>
    </div>
  `;
}, () => {
  bindNavButtons();
  on("btn-import-key", async () => {
    const key = val("import-key-input");
    const name = val("import-name-input");
    if (!key) return toast("Enter a private key", true);
    try {
      await sendMsg({ action: "importPrivateKey", privateKey: key, name: name || undefined });
      toast("Wallet imported!");
      navigate("/wallet");
    } catch (e) { toast(e.message, true); }
  });
});

route("/wallet", () => {
  if (!walletState?.hasWallet) { return ""; }
  const acct = walletState.accounts?.[walletState.activeIndex];
  const addr = acct?.address || walletState.address || "";
  const acctName = acct?.name || "Account";

  return `
    <div>
      <div class="border-b-4 border-black bg-neo-secondary px-4 py-3 flex items-center justify-between">
        <div class="border-4 border-black bg-neo-accent px-3 py-1 shadow-neo-sm -rotate-1">
          <span class="font-black text-sm uppercase tracking-tight">Dice</span>
        </div>

      </div>

      <div class="flex-1 p-4 flex flex-col justify-center bg-grid">
        <div class="border-4 border-black bg-neo-white shadow-neo-lg p-5">
          <a data-nav="/accounts" class="font-black text-lg uppercase tracking-tight mb-3 block cursor-pointer no-underline text-black hover:text-black/70 transition-colors duration-100">${acctName} <span class="text-[9px]">&#9660;</span></a>
          ${label("Address")}
          <div id="display-address" data-full="${addr}" class="font-bold text-sm bg-neo-bg border-4 border-black px-3 py-2 cursor-pointer hover:bg-neo-secondary transition-colors duration-100 break-all" title="Click to copy">
            ${shortAddr(addr)}
          </div>
          <div class="text-center mt-5 mb-2">
            <div class="font-black text-[10px] uppercase tracking-[0.25em] text-black/50 mb-1">Balance</div>
            <div id="display-balance" class="font-black text-4xl tracking-tighter leading-none">--</div>
            <div class="font-black text-xs tracking-wide text-black/50 mt-1 uppercase">ETH</div>
          </div>
          <button id="btn-refresh" class="mt-2 mx-auto block border-4 border-black bg-neo-bg px-4 py-1.5 font-black text-[10px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none hover:bg-neo-secondary">
            Refresh
          </button>
        </div>
      </div>

      <div class="mt-auto">
        <div class="flex border-t-4 border-black">
          <a data-nav="/send" class="flex-1 text-center py-3 font-black text-[11px] uppercase tracking-widest border-r-4 border-black bg-neo-accent hover:brightness-110 transition-all duration-100 cursor-pointer no-underline text-black">Send</a>
          <a data-nav="/export" class="flex-1 text-center py-3 font-black text-[11px] uppercase tracking-widest border-r-4 border-black bg-neo-secondary hover:brightness-95 transition-all duration-100 cursor-pointer no-underline text-black">Export</a>
          <a data-nav="/settings" class="flex-1 text-center py-3 font-black text-[11px] uppercase tracking-widest bg-neo-muted hover:brightness-95 transition-all duration-100 cursor-pointer no-underline text-black">Settings</a>
        </div>
      </div>
    </div>
  `;
}, () => {
  bindNavButtons();

  const addrEl = $("#display-address");
  if (addrEl) {
    addrEl.addEventListener("click", () => {
      navigator.clipboard.writeText(addrEl.dataset.full);
      toast("Address copied!");
    });
  }

  on("btn-refresh", () => refreshBalance());
  refreshBalance();
});

async function refreshBalance() {
  const el = $("#display-balance");
  if (!el) return;
  try {
    const { balance } = await sendMsg({ action: "getBalance" });
    el.textContent = formatBalance(balance);
  } catch {
    el.textContent = "Error";
  }
}

route("/accounts", () => {
  if (!walletState?.hasWallet) return "";
  const accounts = walletState.accounts || [];

  const accountRows = accounts.map((a, i) => {
    const isActive = a.active;
    const bgClass = isActive ? "bg-neo-secondary" : "bg-neo-white hover:bg-neo-bg";
    const activeMarker = isActive ? `<span class="font-black text-[10px] uppercase tracking-widest text-neo-accent">&bull; Active</span>` : "";
    return `
      <div class="border-4 border-black ${bgClass} shadow-neo-sm p-3 flex items-center gap-3 transition-all duration-100">
        <div class="flex-1 min-w-0 cursor-pointer" data-switch-account="${i}">
          <div class="flex items-center gap-2">
            <span class="font-black text-sm uppercase tracking-wide truncate">${a.name}</span>
            ${activeMarker}
          </div>
          <div class="font-bold text-[11px] text-black/50 mt-0.5 truncate">${shortAddr(a.address)}</div>
        </div>
        <button data-rename-account="${i}" class="border-4 border-black bg-neo-bg px-2 py-1 font-black text-[10px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[1px] active:translate-y-[1px] active:shadow-neo-none hover:bg-neo-secondary" title="Rename">
          &#9998;
        </button>
        ${accounts.length > 1 ? `
          <button data-delete-account="${i}" class="border-4 border-black bg-neo-accent/40 px-2 py-1 font-black text-[10px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[1px] active:translate-y-[1px] active:shadow-neo-none hover:bg-neo-accent" title="Delete">
            &#10005;
          </button>
        ` : ""}
      </div>
    `;
  }).join("");

  return `
    <div class="p-5 flex flex-col">
      ${backBtn("WALLET", "/wallet")}

      <div class="border-4 border-black bg-neo-secondary shadow-neo-md px-4 py-2 inline-block mb-5 -rotate-1 self-start">
        <span class="font-black text-lg uppercase tracking-tight">Accounts</span>
      </div>

      <div class="flex flex-col gap-2 mb-4 flex-1 overflow-y-auto" id="account-list">
        ${accountRows}
      </div>

      <div class="flex flex-col gap-2 mt-auto">
        ${btnPrimary("Create New Account", "btn-add-account")}
        <div class="flex gap-2">
          <button id="btn-import-mnemonic-acct" class="flex-1 h-11 border-4 border-black bg-neo-muted font-black text-[10px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none hover:brightness-95">
            + Phrase
          </button>
          <button id="btn-import-key-acct" class="flex-1 h-11 border-4 border-black bg-neo-bg font-black text-[10px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[2px] active:translate-y-[2px] active:shadow-neo-none hover:bg-neo-secondary">
            + Private Key
          </button>
        </div>
      </div>
    </div>
  `;
}, () => {
  bindNavButtons();

  $$("[data-switch-account]").forEach(el => {
    el.addEventListener("click", async () => {
      const idx = parseInt(el.dataset.switchAccount);
      try {
        await sendMsg({ action: "switchAccount", index: idx });
        toast("Switched account");
        navigate("/wallet");
      } catch (e) { toast(e.message, true); }
    });
  });

  $$("[data-rename-account]").forEach(el => {
    el.addEventListener("click", () => {
      navigate("/rename?index=" + el.dataset.renameAccount);
    });
  });

  $$("[data-delete-account]").forEach(el => {
    el.addEventListener("click", async () => {
      const idx = parseInt(el.dataset.deleteAccount);
      const acct = walletState.accounts[idx];
      if (!confirm(`Delete "${acct.name}"? Make sure you have backed up the keys.`)) return;
      try {
        await sendMsg({ action: "deleteAccount", index: idx });
        toast("Account deleted");
        navigate("/accounts");
      } catch (e) { toast(e.message, true); }
    });
  });

  on("btn-add-account", async () => {
    try {
      const { mnemonic } = await sendMsg({ action: "addAccount" });
      currentMnemonic = mnemonic;
      navigate("/export/phrase");
    } catch (e) { toast(e.message, true); }
  });

  on("btn-import-mnemonic-acct", () => navigate("/import/mnemonic"));
  on("btn-import-key-acct", () => navigate("/import/key"));
});

route("/rename", () => {
  if (!walletState?.hasWallet) return "";
  const idx = parseInt(currentParams().index);
  const acct = walletState.accounts?.[idx];
  if (!acct) return "";

  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${backBtn("ACCOUNTS", "/accounts")}

        <div class="border-4 border-black bg-neo-muted shadow-neo-md px-4 py-2 inline-block mb-5 self-start">
          <span class="font-black text-lg uppercase tracking-tight">Rename</span>
        </div>

        <div class="flex flex-col gap-3">
          <div>
            ${label("Current Name")}
            <div class="font-bold text-sm bg-neo-bg border-4 border-black px-3 py-2">${acct.name}</div>
          </div>
          <div>
            ${label("New Name")}
            <input id="rename-input" type="text" value="${acct.name}" class="w-full border-4 border-black bg-neo-white px-3 py-2 font-bold text-sm shadow-neo-sm focus:outline-none focus:bg-neo-secondary transition-colors duration-100" maxlength="32" />
          </div>
          ${btnPrimary("Save", "btn-rename-save")}
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();
  const input = $("#rename-input");
  if (input) { input.focus(); input.select(); }

  on("btn-rename-save", async () => {
    const idx = parseInt(currentParams().index);
    const newName = val("rename-input");
    if (!newName || newName.trim() === "") return toast("Name cannot be empty", true);
    try {
      await sendMsg({ action: "renameAccount", index: idx, name: newName.trim() });
      toast("Renamed!");
      navigate("/accounts");
    } catch (e) { toast(e.message, true); }
  });
});

route("/send", () => {
  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${backBtn("WALLET", "/wallet")}

        <div class="border-4 border-black bg-neo-bg shadow-neo-md px-4 py-2 inline-block mb-5 -rotate-1 self-start">
          <span class="font-black text-lg uppercase tracking-tight text-black/30">Send ETH</span>
        </div>

        <div class="border-4 border-black bg-neo-bg p-4">
          <p class="font-black text-sm uppercase tracking-wide text-black/40">Sending is disabled in this version.</p>
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();
});

route("/export", () => {
  if (!walletState?.hasWallet) return "";
  const hasMnemonic = walletState.hasMnemonic;

  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${backBtn("WALLET", "/wallet")}

        <div class="border-4 border-black bg-neo-muted shadow-neo-md px-4 py-2 inline-block mb-5 rotate-1 self-start">
          <span class="font-black text-lg uppercase tracking-tight">Export</span>
        </div>

        <div class="flex flex-col gap-3">
          ${hasMnemonic ? btnSecondary("Show Recovery Phrase", "btn-go-export-phrase") : ""}
          ${btnOutline("Show Private Key", "btn-go-export-key")}
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();
  on("btn-go-export-phrase", () => navigate("/export/phrase"));
  on("btn-go-export-key", () => navigate("/export/key"));
});

route("/export/phrase", () => {
  if (!walletState?.hasWallet || !walletState.hasMnemonic) return "";
  const isNew = !!currentMnemonic;

  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${isNew ? "" : backBtn("BACK", "/export")}

        <div class="border-4 border-black bg-neo-bg shadow-neo-md p-3 mb-4">
          <div id="export-mnemonic-grid" class="grid grid-cols-3 gap-2 ${isNew ? "" : "blur-sm hover:blur-none"} transition-all duration-300 cursor-pointer"></div>
        </div>

        ${btnOutline("Copy Phrase", "btn-copy-phrase", "mb-3")}

        ${isNew ? `<div class="mt-auto">${btnPrimary("I've Saved My Phrase &rarr;", "btn-phrase-done")}</div>` : ""}
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();
  const isNew = !!currentMnemonic;

  function populateGrid(words) {
    const grid = $("#export-mnemonic-grid");
    if (!grid) return;
    grid.replaceChildren();
    words.forEach((w, i) => {
      const el = document.createElement("div");
      el.className = "border-4 border-black bg-neo-white px-2 py-1.5 text-center font-bold text-xs";
      el.appendChild(document.createTextNode(`${i + 1}. ${w}`));
      grid.appendChild(el);
    });
  }

  if (isNew) {
    populateGrid(currentMnemonic.split(" "));
  } else {
    (async () => {
      try {
        const { mnemonic } = await sendMsg({ action: "exportMnemonic" });
        populateGrid(mnemonic.split(" "));
      } catch (e) { toast(e.message, true); }
    })();
  }

  on("btn-copy-phrase", async () => {
    try {
      const phrase = currentMnemonic || (await sendMsg({ action: "exportMnemonic" })).mnemonic;
      navigator.clipboard.writeText(phrase);
      toast("Copied to clipboard");
    } catch (e) { toast(e.message, true); }
  });

  on("btn-phrase-done", () => {
    currentMnemonic = null;
    navigate("/wallet");
  });
});

route("/export/key", () => {
  if (!walletState?.hasWallet) return "";

  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${backBtn("BACK", "/export")}

        <div class="border-4 border-black bg-neo-accent shadow-neo-md px-4 py-2 inline-block mb-4 rotate-1 self-start">
          <span class="font-black text-lg uppercase tracking-tight">Private Key</span>
        </div>

        <div id="display-privkey" class="border-4 border-black bg-neo-bg shadow-neo-md px-3 py-3 font-bold text-xs break-all blur-sm hover:blur-none transition-all duration-300 cursor-pointer mb-4" style="color: #FF6B6B;"></div>

        ${btnOutline("Copy Key", "btn-copy-export-key")}
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();

  (async () => {
    try {
      const { privateKey } = await sendMsg({ action: "exportPrivateKey" });
      const el = $("#display-privkey");
      if (el) el.textContent = privateKey;
    } catch (e) { toast(e.message, true); }
  })();

  on("btn-copy-export-key", () => {
    const key = $("#display-privkey")?.textContent;
    if (key) {
      navigator.clipboard.writeText(key);
      toast("Copied to clipboard");
    }
  });
});

route("/approve", () => {
  return `
    <div class="flex-1 flex flex-col">
      <div class="border-b-4 border-black bg-neo-accent px-4 py-3 flex items-center gap-2">
        <span class="font-black text-sm uppercase tracking-tight">Connection Request</span>
      </div>

      <div class="flex-1 p-5 flex flex-col justify-center" id="approve-content">
        <div class="text-center mb-4">
          <div class="animate-pulse font-black text-[11px] uppercase tracking-widest opacity-50">Loading...</div>
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, async () => {
  const container = $("#approve-content");
  if (!container) return;

  const p = currentParams();
  if (!p.id) { navigate("/wallet"); return; }

  const accounts = walletState?.accounts || [];
  const activeIdx = walletState?.activeIndex ?? 0;

  const acctOptions = accounts.map((a, i) => {
    const short = a.address.slice(0, 6) + "…" + a.address.slice(-4);
    return `<option value="${i}" ${i === activeIdx ? "selected" : ""}>${a.name} (${short})</option>`;
  }).join("");

  container.innerHTML = `
    <div class="text-center mb-6">
      ${starSvg(20)} 
    </div>

    <div class="border-4 border-black bg-neo-white shadow-neo-lg p-5 mb-5">
      <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Site wants to connect</div>
      <div class="border-4 border-black bg-neo-bg px-3 py-2 font-bold text-sm break-all">${new URL(p.origin).origin}</div>
      <div class="mt-4 text-[11px] font-bold leading-snug opacity-60">
        This will allow the site to see your wallet address.
      </div>
    </div>

    <div class="mb-5">
      <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Connect as</div>
      <select id="approve-acct-select" class="w-full border-4 border-black bg-neo-bg px-3 py-2 font-bold text-sm cursor-pointer outline-none">
        ${acctOptions}
      </select>
    </div>

    <div class="flex flex-col gap-3 mt-auto">
      ${btnPrimary("Connect", "btn-approve")}
      ${btnOutline("Reject", "btn-reject")}
    </div>
  `;

  on("btn-approve", async () => {
    try {
      const sel = $("#approve-acct-select");
      const idx = parseInt(sel.value, 10);
      if (idx !== activeIdx) {
        await sendMsg({ action: "switchAccount", index: idx });
      }
      await sendMsg({ action: "approveConfirmation", id: Number(p.id) });
      window.close();
    } catch (e) { toast(e.message, true); }
  });

  on("btn-reject", async () => {
    try {
      await sendMsg({ action: "rejectConfirmation", id: Number(p.id) });
      window.close();
    } catch (e) { toast(e.message, true); }
  });
});

route("/confirm", () => {
  return `
    <div class="flex-1 flex flex-col">
      <div class="border-b-4 border-black bg-neo-accent px-4 py-3 flex items-center gap-2">
        <span class="font-black text-sm uppercase tracking-tight">Confirm Action</span>
      </div>
      <div class="flex-1 p-5 flex flex-col" id="confirm-content">
        <div class="text-center mb-4">
          <div class="animate-pulse font-black text-[11px] uppercase tracking-widest opacity-50">Loading...</div>
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, async () => {
  const container = $("#confirm-content");
  if (!container) return;

  const p = currentParams();
  if (!p.id || !p.type) { window.close(); return; }

  let title, detailsHtml;

  if (p.type === "personal_sign") {
    title = "Sign Message";
    detailsHtml = `
      <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Message</div>
      <div class="border-4 border-black bg-neo-bg px-3 py-3 font-mono text-xs break-all max-h-[30vh] overflow-y-auto">${p.message}</div>
    `;
  } else if (p.type === "eth_signTypedData_v4") {
    title = "Sign Typed Data";
    let d = {};
    try { d = JSON.parse(p.details || "{}"); } catch {}
    const domainStr = d.domain ? JSON.stringify(d.domain, null, 2) : "—";
    const messageStr = d.message ? JSON.stringify(d.message, null, 2) : "—";
    detailsHtml = `
      <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Domain</div>
      <div class="border-4 border-black bg-neo-bg px-3 py-2 font-mono text-[10px] break-all max-h-[15vh] overflow-y-auto mb-3">${domainStr}</div>
      <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Message</div>
      <div class="border-4 border-black bg-neo-bg px-3 py-2 font-mono text-[10px] break-all max-h-[20vh] overflow-y-auto">${messageStr}</div>
    `;
  } else if (p.type === "eth_sendTransaction") {
    title = "Send Transaction";
    detailsHtml = `
      <div class="flex justify-between items-center mb-3">
        <span class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50">To</span>
        <span class="font-mono text-xs">${p.to}</span>
      </div>
      <div class="flex justify-between items-center mb-3">
        <span class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50">Value</span>
        <span class="font-bold text-sm">${p.value} ETH</span>
      </div>
      ${p.data && p.data !== "0x" ? `
        <div class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50 mb-2">Data</div>
        <div class="border-4 border-black bg-neo-bg px-3 py-2 font-mono text-[10px] break-all max-h-[15vh] overflow-y-auto">${p.data}</div>
      ` : ""}
    `;
  } else {
    title = "Unknown Request";
    detailsHtml = `<div class="font-mono text-xs break-all">${JSON.stringify(p, null, 2)}</div>`;
  }

  container.innerHTML = `
    <div class="text-center mb-4">
      ${starSvg(20)}
    </div>

    <div class="border-4 border-black bg-neo-white shadow-neo-lg p-4 mb-4">
      <div class="font-black text-sm uppercase tracking-tight mb-3">${title}</div>
      <div class="flex justify-between items-center mb-3">
        <span class="font-black text-[10px] uppercase tracking-[0.2em] text-black/50">Origin</span>
        <span class="font-bold text-xs">${p.origin}</span>
      </div>
      ${detailsHtml}
    </div>

    <div class="flex flex-col gap-3 mt-auto">
      ${p.type === "eth_sendTransaction"
        ? `<button disabled class="w-full h-14 border-4 border-black bg-neo-bg font-black text-[11px] uppercase tracking-widest text-black/30 cursor-not-allowed">Sending Disabled</button>`
        : btnPrimary("Sign", "btn-confirm")}
      ${btnOutline("Reject", "btn-reject-confirm")}
    </div>
  `;

  on("btn-confirm", async () => {
    try {
      await sendMsg({ action: "approveConfirmation", id: Number(p.id) });
      window.close();
    } catch (e) { toast(e.message, true); }
  });

  on("btn-reject-confirm", async () => {
    try {
      await sendMsg({ action: "rejectConfirmation", id: Number(p.id) });
      window.close();
    } catch (e) { toast(e.message, true); }
  });
});

route("/settings", () => {
  if (!walletState?.hasWallet) return "";

  const connected = walletState.connectedSites || [];
  const privileged = walletState.onboardOrigins || [];

  const connectedRows = connected.length > 0
    ? connected.map(site => `
        <div class="flex items-center gap-2 border-4 border-black bg-neo-white px-3 py-2 shadow-neo-sm">
          <span class="flex-1 font-bold text-[11px] truncate">${site}</span>
          <button data-disconnect="${site}" class="border-4 border-black bg-neo-accent/40 px-2 py-0.5 font-black text-[9px] uppercase tracking-widest shadow-neo-sm cursor-pointer transition-all duration-100 active:translate-x-[1px] active:translate-y-[1px] active:shadow-neo-none hover:bg-neo-accent">&#10005;</button>
        </div>
      `).join("")
    : `<div class="text-[11px] font-bold opacity-40 uppercase tracking-wide">No connected sites</div>`;

  const privilegedRows = privileged.length > 0
    ? privileged.map(site => `
        <div class="border-4 border-black bg-neo-muted/30 px-3 py-2 shadow-neo-sm">
          <span class="font-bold text-[11px] truncate">${site}</span>
        </div>
      `).join("")
    : `<div class="text-[11px] font-bold opacity-40 uppercase tracking-wide">None</div>`;

  return `
    <div class="flex-1 flex flex-col">
      <div class="flex-1 p-5">
        ${backBtn("WALLET", "/wallet")}

        <div class="border-4 border-black bg-neo-white shadow-neo-md px-4 py-2 inline-block mb-5 self-start">
          <span class="font-black text-lg uppercase tracking-tight">Settings</span>
        </div>

        <div class="border-4 border-black bg-neo-bg p-4 shadow-neo-md mb-4 bg-grid">
          <div class="font-black text-[11px] uppercase tracking-[0.2em] mb-2 opacity-50">Wallet Address</div>
          <div class="font-bold text-xs break-all">${walletState.address}</div>
        </div>

        <div class="border-4 border-black bg-neo-bg p-4 shadow-neo-md mb-4">
          <div class="font-black text-[11px] uppercase tracking-[0.2em] mb-2 opacity-50">RPC URL</div>
          <div class="font-bold text-xs break-all">${walletState.rpcUrl}</div>
        </div>

        <div class="mb-4">
          ${label("Connected Sites")}
          <div class="flex flex-col gap-1.5">
            ${connectedRows}
          </div>
        </div>

        <div class="mb-6">
          ${label("Privileged Origins")}
          <div class="flex flex-col gap-1.5">
            ${privilegedRows}
          </div>
          <div class="text-[10px] font-bold opacity-40 mt-1">These origins can create and manage accounts.</div>
        </div>

        <div class="mt-auto">
          <div class="border-4 border-black bg-neo-accent/20 p-4 mb-4">
            <div class="font-black text-xs uppercase tracking-wide mb-1">Danger Zone</div>
            <div class="text-[11px] font-bold leading-snug mb-3 opacity-70">This will permanently delete ALL accounts. Back up your keys first.</div>
            ${btnDanger("Reset Wallet", "btn-reset")}
          </div>
        </div>
      </div>

      ${acctBar()}
    </div>
  `;
}, () => {
  bindNavButtons();

  $$("[data-disconnect]").forEach(el => {
    el.addEventListener("click", async () => {
      const site = el.dataset.disconnect;
      try {
        await sendMsg({ action: "disconnectSite", origin: site });
        toast("Disconnected " + site);
        navigate("/settings");
      } catch (e) { toast(e.message, true); }
    });
  });

  on("btn-reset", async () => {
    if (!confirm("This will permanently delete ALL accounts. Make sure you have backed up your recovery phrases and private keys.")) return;
    try {
      await sendMsg({ action: "resetWallet" });
      toast("Wallet reset");
      navigate("/onboard");
    } catch (e) { toast(e.message, true); }
  });
});

function on(id, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener("click", handler);
}

function val(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : "";
}

document.addEventListener("DOMContentLoaded", handleRoute);
