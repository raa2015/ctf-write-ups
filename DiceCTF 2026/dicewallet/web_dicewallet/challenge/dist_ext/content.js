const script = document.createElement("script");
script.src = chrome.runtime.getURL("inpage.js");
const secret = Array.from(
  crypto.getRandomValues(new Uint8Array(32)),
  (b) => b.toString(16).padStart(2, "0")
).join("");
script.setAttribute("data-secret", secret);
(document.head || document.documentElement).appendChild(script);
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  if (event.data?.type !== "DICE_REQUEST") return;
  const data = event.data;
  data.type = "DICE_PROVIDER_REQUEST";
  chrome.runtime.sendMessage(data);
});
chrome.runtime.onMessage.addListener((result) => {
  if (result.type === "DICE_RESPONSE") {
    result.fn = "dwOnMessage";
  } else if (result.type === "DICE_ERROR") {
    result.fn = "dwOnError";
  }
  result.secret = secret;
  window.postMessage(result, location.origin);
});
function signalReady() {
  window.postMessage({ fn: "dwOnReady", secret }, location.origin);
}
signalReady();
document.addEventListener("DOMContentLoaded", signalReady);
window.addEventListener("load", signalReady);
