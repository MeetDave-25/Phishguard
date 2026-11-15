// Auto-checks each page you open (rule-based + reputation only; no AI, so nothing is sent to third parties by default).
const API = "http://127.0.0.1:5000/api/analyze";
const cache = new Map(); // url -> {verdict, score, at}
const COLORS = { safe: "#22c55e", suspicious: "#f59e0b", dangerous: "#ef4444" };

async function check(url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < 10 * 60 * 1000) return hit;
  const r = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ input: url }) });
  const d = await r.json();
  const res = { verdict: d.verdict, score: d.score, at: Date.now() };
  cache.set(url, res);
  return res;
}

async function badge(tabId, url) {
  if (!/^https?:\/\//i.test(url) || /^https?:\/\/(127\.0\.0\.1|localhost)/i.test(url)) {
    return chrome.action.setBadgeText({ tabId, text: "" });
  }
  try {
    const { verdict, score } = await check(url);
    chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[verdict] });
    chrome.action.setBadgeText({ tabId, text: verdict === "safe" ? "" : verdict === "dangerous" ? "!!" : "?" });
    chrome.action.setTitle({ tabId, title: `PhishGuard: ${verdict} (risk ${score}/100)` });
  } catch {
    chrome.action.setBadgeText({ tabId, text: "" }); // server not running
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => { if (info.status === "complete" && tab.url) badge(tabId, tab.url); });
