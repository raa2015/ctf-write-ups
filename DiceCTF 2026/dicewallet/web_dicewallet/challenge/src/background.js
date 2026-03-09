import { ethers } from "ethers";

const DEFAULT_RPC_URL = "https://eth.llamarpc.com";
const CHAIN_ID = "0x1";

let rpcUrl = DEFAULT_RPC_URL;

const DEFAULT_ONBOARD_ORIGINS = [
  "http://localhost:8080"
];

let wallet = {
  accounts: [],
  activeIndex: 0,
  connectedSites: {},
  onboardOrigins: [...DEFAULT_ONBOARD_ORIGINS]
};

function activeAccount() {
  return wallet.accounts[wallet.activeIndex] || null;
}

async function loadWallet() {
  const data = await chrome.storage.local.get(["accounts", "activeIndex", "connectedSites", "onboardOrigins", "rpcUrl"]);

  if (data.accounts) wallet.accounts = data.accounts;
  if (typeof data.activeIndex === "number") wallet.activeIndex = data.activeIndex;
  if (data.connectedSites) wallet.connectedSites = data.connectedSites;
  if (data.onboardOrigins) wallet.onboardOrigins = data.onboardOrigins;
  if (data.rpcUrl) rpcUrl = data.rpcUrl;

  wallet.accounts = wallet.accounts.map(a => buildAccount(a.name, a.mnemonic, a.privateKey));
}

function buildAccount(name, mnemonic, privateKey) {
  let pk = privateKey;
  let addr = null;
  if (mnemonic) {
    const hd = ethers.HDNodeWallet.fromPhrase(mnemonic);
    pk = hd.privateKey.slice(2);
    addr = hd.address;
  } else if (pk) {
    const w = new ethers.Wallet("0x" + pk.replace(/^0x/, ""));
    pk = w.privateKey.slice(2);
    addr = w.address;
  }
  return { name, mnemonic: mnemonic || null, privateKey: pk, address: addr };
}

async function saveWallet() {
  await chrome.storage.local.set({
    accounts: wallet.accounts.map(a => ({
      name: a.name,
      mnemonic: a.mnemonic,
      privateKey: a.privateKey
    })),
    activeIndex: wallet.activeIndex,
    connectedSites: wallet.connectedSites,
    onboardOrigins: wallet.onboardOrigins
  });
}

function getEthersWallet() {
  const acct = activeAccount();
  if (!acct?.privateKey) return null;
  return new ethers.Wallet("0x" + acct.privateKey);
}

function nextAccountName() {
  return `Account ${wallet.accounts.length + 1}`;
}

async function generateNewWallet() {
  const hdWallet = ethers.HDNodeWallet.createRandom();
  const acct = buildAccount(nextAccountName(), hdWallet.mnemonic.phrase, null);
  wallet.accounts.push(acct);
  wallet.activeIndex = wallet.accounts.length - 1;
  await saveWallet();
  return { address: acct.address, mnemonic: acct.mnemonic };
}

async function importFromMnemonic(phrase, name) {
  const trimmed = phrase.trim().toLowerCase();
  if (!ethers.Mnemonic.isValidMnemonic(trimmed)) {
    throw new Error("Invalid mnemonic phrase");
  }
  const acct = buildAccount(name || nextAccountName(), trimmed, null);
  wallet.accounts.push(acct);
  wallet.activeIndex = wallet.accounts.length - 1;
  await saveWallet();
  return acct.address;
}

async function importFromPrivateKey(privKeyHex, name) {
  const clean = privKeyHex.startsWith("0x") ? privKeyHex.slice(2) : privKeyHex;
  const acct = buildAccount(name || nextAccountName(), null, clean);
  wallet.accounts.push(acct);
  wallet.activeIndex = wallet.accounts.length - 1;
  await saveWallet();
  return acct.address;
}

async function rpcCall(method, params = []) {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}

let confirmId = 0;
const pendingConfirmations = new Map();
let popupWindowId = null;
let popupTabId = null;

function nextConfirmId() { return ++confirmId; }

function requestConfirmation(id, route) {
  const url = chrome.runtime.getURL(`popup.html#${route}`);
  return new Promise((resolve, reject) => {
    pendingConfirmations.set(id, { resolve, reject, windowId: null });

    if (popupWindowId !== null) {
      chrome.windows.get(popupWindowId).then(() => {
        chrome.tabs.update(popupTabId, { url });
        chrome.windows.update(popupWindowId, { focused: true });
        const entry = pendingConfirmations.get(id);
        if (entry) entry.windowId = popupWindowId;
      }).catch(() => {
        popupWindowId = null;
        popupTabId = null;
        openPopupWindow(id, url, reject);
      });
    } else {
      openPopupWindow(id, url, reject);
    }
  });
}

function openPopupWindow(id, url, reject) {
  chrome.windows.create({
    url,
    type: "popup",
    width: 390,
    height: 620,
    focused: true
  }).then(win => {
    popupWindowId = win.id;
    popupTabId = win.tabs[0].id;
    const entry = pendingConfirmations.get(id);
    if (entry) entry.windowId = win.id;
  }).catch(() => {
    pendingConfirmations.delete(id);
    reject(new Error("Failed to open confirmation window"));
  });
}

chrome.windows.onRemoved.addListener((windowId) => {
  if (windowId === popupWindowId) {
    popupWindowId = null;
    popupTabId = null;
  }
  for (const [id, c] of pendingConfirmations) {
    if (c.windowId === windowId) {
      pendingConfirmations.delete(id);
      c.reject(new Error("User rejected the request"));
    }
  }
});

const RPC_FORWARD = new Set([
  "eth_blockNumber",
  "eth_call",
  "eth_estimateGas",
  "eth_gasPrice",
  "eth_getBalance",
  "eth_getBlockByHash",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getLogs",
  "eth_getStorageAt",
  "eth_getTransactionByHash",
  "eth_getTransactionCount",
  "eth_getTransactionReceipt",
  "eth_maxPriorityFeePerGas",
  "eth_feeHistory",
]);

async function handleProviderRequest(method, params, origin) {
  switch (method) {
    case "eth_requestAccounts":
    case "eth_accounts": {
      if (wallet.accounts.length === 0) return [];
      if (method === "eth_requestAccounts" && !isConnected(origin)) {
        const cid = nextConfirmId();
        await requestConfirmation(cid, `/approve?id=${cid}&origin=${encodeURIComponent(origin)}`);
        wallet.connectedSites[origin] = true;
        await saveWallet();
      }
      if (!isConnected(origin)) return [];
      const active = activeAccount();
      const rest = wallet.accounts.filter((_, i) => i !== wallet.activeIndex);
      return [active, ...rest].map(a => a.address);
    }

    case "eth_chainId":
      return CHAIN_ID;

    case "net_version":
      return String(parseInt(CHAIN_ID, 16));

    case "personal_sign": {
      if (!isConnected(origin)) throw new Error("Unauthorized - call eth_requestAccounts first");
      const w = getEthersWallet();
      if (!w) throw new Error("No wallet");
      const msgHex = params[0];
      const msgBytes = ethers.getBytes(msgHex);
      let msgText;
      try { msgText = ethers.toUtf8String(msgBytes); } catch { msgText = msgHex; }
      const cid = nextConfirmId();
      await requestConfirmation(cid, `/confirm?id=${cid}&type=personal_sign&origin=${encodeURIComponent(origin)}&message=${encodeURIComponent(msgText)}`);
      return w.signMessage(msgBytes);
    }

    case "eth_signTypedData_v4": {
      if (!isConnected(origin)) throw new Error("Unauthorized - call eth_requestAccounts first");
      const w = getEthersWallet();
      if (!w) throw new Error("No wallet");
      const typedData = typeof params[1] === "string" ? JSON.parse(params[1]) : params[1];
      const { domain, types, message } = typedData;
      const cid = nextConfirmId();
      await requestConfirmation(cid, `/confirm?id=${cid}&type=eth_signTypedData_v4&origin=${encodeURIComponent(origin)}&details=${JSON.stringify({ domain, types, message })}`);
      const sigTypes = { ...types };
      delete sigTypes.EIP712Domain;
      return w.signTypedData(domain, sigTypes, message);
    }

    case "eth_sendTransaction":
      throw new Error("Sending transactions is disabled");

    case "wallet_revokePermissions": {
      delete wallet.connectedSites[origin];
      await saveWallet();
      return { ok: true };
    }

    case "wallet_generate": {
      requireAllowedOrigin(origin);
      const result = await generateNewWallet();
      return { address: result.address, mnemonic: result.mnemonic };
    }

    case "wallet_importMnemonic": {
      requireAllowedOrigin(origin);
      const phrase = params[0]?.mnemonic || params[0];
      const name = params[0]?.name;
      const addr = await importFromMnemonic(phrase, name);
      return { address: addr };
    }

    case "wallet_importPrivateKey": {
      requireAllowedOrigin(origin);
      const key = params[0]?.privateKey || params[0];
      const name = params[0]?.name;
      const addr = await importFromPrivateKey(key, name);
      return { address: addr };
    }

    case "wallet_getState": {
      requireAllowedOrigin(origin);
      return {
        hasWallet: wallet.accounts.length > 0,
        accounts: wallet.accounts.map((a, i) => ({
          name: a.name,
          address: a.address,
          active: i === wallet.activeIndex
        })),
        activeIndex: wallet.activeIndex
      };
    }

    case "wallet_switchAccount": {
      requireAllowedOrigin(origin);
      const idx = params[0]?.index ?? params[0];
      if (idx < 0 || idx >= wallet.accounts.length) throw new Error("Invalid account index");
      wallet.activeIndex = idx;
      await saveWallet();
      return { activeIndex: idx };
    }

    case "wallet_renameAccount": {
      requireAllowedOrigin(origin);
      const rIdx = params[0]?.index ?? 0;
      const rName = params[0]?.name;
      if (rIdx < 0 || rIdx >= wallet.accounts.length) throw new Error("Invalid account index");
      if (!rName) throw new Error("Name required");
      wallet.accounts[rIdx].name = rName;
      await saveWallet();
      return { ok: true };
    }

    case "wallet_setRpcUrl": {
      requireAllowedOrigin(origin);
      const url = params[0]?.url || params[0];
      if (!url) throw new Error("URL required");
      rpcUrl = url;
      await chrome.storage.local.set({ rpcUrl });
      return { ok: true, rpcUrl };
    }

    case "wallet_deleteAccount": {
      requireAllowedOrigin(origin);
      if (wallet.accounts.length <= 1) throw new Error("Cannot delete last account");
      const dIdx = params[0]?.index ?? params[0];
      if (dIdx < 0 || dIdx >= wallet.accounts.length) throw new Error("Invalid account index");
      wallet.accounts.splice(dIdx, 1);
      if (wallet.activeIndex >= wallet.accounts.length) wallet.activeIndex = wallet.accounts.length - 1;
      await saveWallet();
      return { ok: true };
    }

    default:
      if (RPC_FORWARD.has(method)) return rpcCall(method, params);
      throw new Error("Method not supported: " + method);
  }
}

function isConnected(origin) {
  return !!wallet.connectedSites[origin] || wallet.onboardOrigins.includes(origin);
}

function requireAllowedOrigin(origin) {
  if (!wallet.onboardOrigins.includes(origin)) {
    throw new Error("Origin not allowed: " + origin);
  }
}

async function handleRequest(msg, origin) {
  try {
    const response = await handleProviderRequest(msg.method, msg.params || [], origin);
    if (response) {
      msg.type = "DICE_RESPONSE";
      msg.result = response;
    }
  } catch (err) {
    msg.type = "DICE_ERROR";
    msg.error = err.message;
  }
  return msg;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DICE_PROVIDER_REQUEST") {
    const tabId = sender.tab?.id;
    const origin = sender.origin || "unknown";
    if (!tabId) return;
    
    handleRequest(msg, origin).then(result => {
      chrome.tabs.sendMessage(tabId, result);
    });
    return false;
  }

  if (msg.type === "DICE_POPUP") {
    if (!sender.url?.startsWith(chrome.runtime.getURL(""))) return;
    handlePopupMessage(msg)
      .then(result => sendResponse({ result }))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }
});

async function handlePopupMessage(msg) {
  const acct = activeAccount();

  switch (msg.action) {
    case "getState":
      return {
        address: acct?.address || null,
        hasWallet: wallet.accounts.length > 0,
        hasMnemonic: !!acct?.mnemonic,
        accounts: wallet.accounts.map((a, i) => ({
          name: a.name,
          address: a.address,
          hasMnemonic: !!a.mnemonic,
          active: i === wallet.activeIndex
        })),
        activeIndex: wallet.activeIndex,
        connectedSites: Object.keys(wallet.connectedSites).filter(k => wallet.connectedSites[k]),
        onboardOrigins: wallet.onboardOrigins,
        rpcUrl
      };

    case "approveConfirmation": {
      const c = pendingConfirmations.get(msg.id);
      if (!c) throw new Error("No pending confirmation with that ID");
      pendingConfirmations.delete(msg.id);
      c.resolve();
      return { ok: true };
    }

    case "rejectConfirmation": {
      const c = pendingConfirmations.get(msg.id);
      if (!c) throw new Error("No pending confirmation with that ID");
      pendingConfirmations.delete(msg.id);
      c.reject(new Error("User rejected the request"));
      return { ok: true };
    }

    case "generate":
      return await generateNewWallet();

    case "importMnemonic":
      return { address: await importFromMnemonic(msg.mnemonic, msg.name) };

    case "importPrivateKey":
      return { address: await importFromPrivateKey(msg.privateKey, msg.name) };

    case "getBalance": {
      if (!acct?.address) return { balance: "0x0" };
      const balance = await rpcCall("eth_getBalance", [acct.address, "latest"]);
      return { balance };
    }

    case "switchAccount": {
      const idx = msg.index;
      if (idx < 0 || idx >= wallet.accounts.length) throw new Error("Invalid account index");
      wallet.activeIndex = idx;
      await saveWallet();
      return { activeIndex: idx };
    }

    case "renameAccount": {
      const idx2 = msg.index;
      if (idx2 < 0 || idx2 >= wallet.accounts.length) throw new Error("Invalid account index");
      wallet.accounts[idx2].name = msg.name;
      await saveWallet();
      return { ok: true };
    }

    case "deleteAccount": {
      if (wallet.accounts.length <= 1) throw new Error("Cannot delete last account");
      const idx3 = msg.index;
      if (idx3 < 0 || idx3 >= wallet.accounts.length) throw new Error("Invalid account index");
      wallet.accounts.splice(idx3, 1);
      if (wallet.activeIndex >= wallet.accounts.length) wallet.activeIndex = wallet.accounts.length - 1;
      await saveWallet();
      return { ok: true };
    }

    case "addAccount": {
      return await generateNewWallet();
    }

    case "exportPrivateKey":
      if (!acct?.privateKey) throw new Error("No wallet");
      return { privateKey: "0x" + acct.privateKey };

    case "exportMnemonic":
      if (!acct?.mnemonic) throw new Error("No mnemonic available (wallet was imported via private key)");
      return { mnemonic: acct.mnemonic };

    case "disconnectSite": {
      const site = msg.origin;
      if (site) {
        delete wallet.connectedSites[site];
        await saveWallet();
      }
      return { ok: true };
    }

    case "resetWallet":
      wallet = {
        accounts: [],
        activeIndex: 0,
        connectedSites: {},
        onboardOrigins: [...DEFAULT_ONBOARD_ORIGINS]
      };
      await chrome.storage.local.clear();
      return { ok: true };

    default:
      throw new Error("Unknown action: " + msg.action);
  }
}

loadWallet();
