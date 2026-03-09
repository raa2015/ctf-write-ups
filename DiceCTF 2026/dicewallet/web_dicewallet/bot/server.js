const express = require("express");
const path = require("path");
const firefox = require("selenium-webdriver/firefox");
const { Builder } = require("selenium-webdriver");
const { ethers } = require("ethers");

const FLAG = process.env.FLAG || "flag{test_flag}";
const PORT = 8080;
const VISIT_TIMEOUT = 45 * 1000;
const MAX_CONCURRENT = 3;
const RPC_URL = process.env.RPC_URL || "";

const EXT_PATH = path.resolve(__dirname, "../challenge/dist_ext");

let adminMnemonic = null;
if (process.env.ADMIN_MNEMONIC) {
  adminMnemonic = process.env.ADMIN_MNEMONIC.trim();
  console.log("[bot] Using provided mnemonic:", adminMnemonic);
} else {
  const wallet = ethers.Wallet.createRandom();
  adminMnemonic = wallet.mnemonic.phrase;
  console.log("[bot] Random mnemonic generated:", adminMnemonic);
}

let activeVisits = 0;

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

process.on("uncaughtException", (e) => console.error("Uncaught exception:", e.message));
process.on("unhandledRejection", (e) => console.error("Unhandled rejection:", e));

function buildOptions() {
  const options = new firefox.Options();
  options.addArguments("--headless");
  options.setPreference("xpinstall.signatures.required", false);
  options.setPreference("extensions.autoDisableScopes", 0);
  options.setPreference("extensions.enabledScopes", 15);
  if (process.env.FIREFOX_BINARY) {
    options.setBinary(process.env.FIREFOX_BINARY);
  }
  return options;
}

async function launchBrowser() {
  const driver = await new Builder()
    .forBrowser("firefox")
    .setFirefoxOptions(buildOptions())
    .build();
  await driver.installAddon(EXT_PATH, true);
  return driver;
}

async function setupWallet(driver) {
  await driver.get(`http://localhost:${PORT}`);
  await driver.wait(async () => {
    return driver.executeScript("return !!window.ethereum");
  }, 15000);
  if (RPC_URL) {
    await driver.executeScript(
      `return window.ethereum.request({
        method: "wallet_setRpcUrl",
        params: [{ url: arguments[0] }],
      });`,
      RPC_URL
    );
  }
  await driver.executeScript(
    `return window.ethereum.request({
      method: "wallet_importMnemonic",
      params: [{ mnemonic: arguments[0], name: "Admin" }],
    });`,
    adminMnemonic
  );
}

app.post("/visit", async (req, res) => {
  const url = (req.body.url || "").trim();

  if (!url) return res.json({ error: "URL is required" });
  if (!/^https?:\/\//i.test(url)) return res.json({ error: "URL must start with http:// or https://" });
  if (activeVisits >= MAX_CONCURRENT) return res.json({ error: `Too many concurrent visits (max ${MAX_CONCURRENT}). Try again later.` });

  activeVisits++;
  res.json({ ok: true, message: `Visiting ${url} for up to ${VISIT_TIMEOUT / 1000} seconds... (${activeVisits}/${MAX_CONCURRENT} active)` });

  let driver = null;
  try {
    driver = await launchBrowser();
    await setupWallet(driver);
    console.log("[bot] Visiting:", url);
    await driver.get(url);
    await driver.wait(async () => {
      try {
        return (await driver.getCurrentUrl()) === "about:blank";
      } catch { return true; }
    }, VISIT_TIMEOUT).catch(() => {});
    console.log("[bot] Visit complete");
  } catch (e) {
    console.error("Visit error:", e.message);
  } finally {
    if (driver) try { await driver.quit(); } catch {}
    activeVisits--;
  }
});

app.get("/status", (req, res) => {
  res.json({ ready: true, activeVisits, maxConcurrent: MAX_CONCURRENT });
});

app.post("/flag", (req, res) => {
  const mnemonic = (req.body.mnemonic || "").trim();
  if (!mnemonic || !adminMnemonic) return res.json({ error: "Mnemonic is required" });
  if (mnemonic === adminMnemonic) {
    return res.json({ flag: FLAG });
  }
  return res.json({ error: "Incorrect mnemonic" });
});

app.listen(PORT, () => {
  console.log(`web/dicewallet listening on http://localhost:${PORT}`);
});
