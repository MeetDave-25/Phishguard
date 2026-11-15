const API = "http://127.0.0.1:5000/api/analyze";
const COLOR = { safe: "#22c55e", suspicious: "#f59e0b", dangerous: "#ef4444" };
const LABEL = { safe: "Looks safe", suspicious: "Be careful", dangerous: "Likely a scam" };
const DOT = { high: "#ef4444", medium: "#f59e0b", low: "#60a5fa", good: "#22c55e" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let url = "";

async function run(live) {
  const main = document.getElementById("main");
  main.innerHTML = "";
  try {
    const r = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ input: url, live }) });
    const d = await r.json();
    const c = COLOR[d.verdict];
    main.innerHTML = `<div class="head"><div class="score" style="color:${c};border-color:${c}">${d.score}</div>
      <div><div class="v" style="color:${c}">${LABEL[d.verdict]}</div><small style="color:#8b93ad">Risk score out of 100</small></div></div>` +
      d.findings.filter((f) => f.level !== "good").slice(0, 5).map((f) =>
        `<div class="f"><i style="background:${DOT[f.level]}"></i><div><b>${esc(f.title)}</b><small>${esc(f.detail)}</small></div></div>`).join("");
  } catch {
    main.innerHTML = '<p class="err">Can’t reach the PhishGuard server.<br>Start it with <code>python app.py</code> in D:\cyber.</p>';
  }
}

chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  url = tab?.url || "";
  document.getElementById("url").textContent = url;
  if (!/^https?:\/\//i.test(url)) { document.getElementById("main").innerHTML = '<p class="err">Open a website to check it.</p>'; return; }
  run(false);
});
document.getElementById("deep").onclick = async (e) => { e.target.disabled = true; e.target.textContent = "Scanning…"; await run(true); e.target.textContent = "Deep scan done ✓"; };
