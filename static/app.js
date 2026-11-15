const $ = (s) => document.querySelector(s);
const input = $("#input"), go = $("#go"), out = $("#result"), live = $("#live"), aiBox = $("#ai"), inspect = $("#inspect"), drop = $("#drop"), fileIn = $("#file");
let image = null;

// theme
const root = document.documentElement;
const sysDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
try { root.dataset.theme = localStorage.getItem("theme") || (sysDark ? "dark" : "light"); } catch { root.dataset.theme = sysDark ? "dark" : "light"; }
$("#theme").onclick = () => {
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch {}
};

document.querySelectorAll(".chip").forEach((c) => (c.onclick = () => { input.value = c.dataset.example; run(); }));
input.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
go.onclick = run;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const COPY = {
  safe: ["Looks safe", "No strong scam signals found. Still, only enter passwords on sites you reached by typing the address yourself."],
  suspicious: ["Be careful", "Several warning signs. Don’t enter personal details or payments until you verify through the official website or app."],
  dangerous: ["Likely a scam", "Strong phishing/scam indicators. Do not click, reply, or share any code. Delete it and report it."],
};
const COLOR = { safe: "#22c55e", suspicious: "#f59e0b", dangerous: "#ff4a1c" };

fetch("/api/status").then((r) => r.json()).then((st) => {
  if (st.ai) { aiBox.disabled = false; aiBox.checked = true; $("#ai-note").textContent = "(Claude · text is sent to Anthropic)"; }
  else $("#ai-toggle").style.display = "none";
  const dot = (on, t) => `<span class="${on ? "on" : ""}"><i></i>${t}</span>`;
  $("#intel").innerHTML = dot(st.openphish, "OpenPhish feed") + dot(st.dns, "Cloudflare security DNS") + dot(st.safe_browsing, "Google Safe Browsing") + dot(st.ocr, "Screenshot OCR");
}).catch(() => {});

function setImage(f) {
  if (!f || !f.type.startsWith("image/")) return;
  image = f; $("#fname").textContent = f.name || "pasted-image.png";
}
fileIn.onchange = () => setImage(fileIn.files[0]);
["dragenter", "dragover"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (ev) => setImage(ev.dataTransfer.files[0]));
document.addEventListener("paste", (ev) => {
  const f = [...(ev.clipboardData?.files || [])].find((x) => x.type.startsWith("image/"));
  if (f) { setImage(f); run(); }
});
input.addEventListener("input", () => { if (input.value) { image = null; $("#fname").textContent = ""; } });

async function run() {
  const value = input.value.trim();
  if (!value && !image) { input.focus(); return; }
  go.disabled = true;
  go.innerHTML = '<span class="spinner"></span> Analyzing…';
  try {
    let r;
    if (image && !value) {
      const fd = new FormData();
      fd.append("image", image); fd.append("live", live.checked ? "1" : "0"); fd.append("ai", aiBox.checked ? "1" : "0"); fd.append("inspect", inspect.checked ? "1" : "0");
      r = await fetch("/api/analyze-image", { method: "POST", body: fd });
    } else {
      r = await fetch("/api/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: value, live: live.checked, ai: aiBox.checked, inspect: inspect.checked }),
      });
    }
    render(await r.json());
  } catch (e) {
    out.className = "result card"; out.innerHTML = "<b>Something went wrong.</b> Is the server running?";
  } finally {
    go.disabled = false;
    go.innerHTML = 'Analyze <span class="kbd">Ctrl ↵</span>';
  }
}

const inspHTML = (ins) => {
  if (!ins) return "";
  const hops = ins.chain || [];
  let h = "";
  if (hops.length > 1) {
    h += `<div class="chain">` + hops.map((c, i) => `<div class="hop"><span class="hop-n">${i + 1}</span><span class="hop-u">${esc(c.url)}</span>
      <span class="hop-s">${c.status ? esc(c.status) : esc(c.error || "")}${c.via ? " · " + esc(c.via) : ""}</span></div>`).join("") + `</div>`;
  }
  if (ins.fetched) {
    h += `<p class="v-sub gap">Page title: <b>${esc(ins.title || "(none)")}</b> · ${ins.forms} form${ins.forms === 1 ? "" : "s"}${ins.has_password ? " · asks for a password" : ""}</p>`;
  } else if (ins.error) {
    h += `<p class="v-sub gap">Page not inspected: ${esc(ins.error)}. That is not a sign of safety: scam sites often block scanners or vanish within hours.</p>`;
  }
  return h;
};
const finding = (f) => `
  <div class="finding l-${f.level}"><span class="dot"></span>
    <div><b>${esc(f.title)}</b><p>${esc(f.detail)}</p></div>
    ${f.points ? `<span class="pts">${f.points > 0 ? "+" : ""}${f.points}</span>` : ""}
  </div>`;

function gauge(score, verdict) {
  const R = 56, C = 2 * Math.PI * R;
  return `<div class="gauge">
    <svg width="132" height="132" viewBox="0 0 132 132">
      <circle class="bg" cx="66" cy="66" r="${R}" fill="none" stroke-width="11"/>
      <circle class="fg" id="arc" cx="66" cy="66" r="${R}" fill="none" stroke-width="11" stroke-linecap="round"
        stroke="${COLOR[verdict]}" stroke-dasharray="${C}" stroke-dashoffset="${C}" data-target="${C * (1 - score / 100)}"/>
    </svg>
    <div class="num"><div>${score}<small>RISK</small></div></div></div>`;
}

function render(d) {
  if (d.error) { out.className = "result card"; out.innerHTML = esc(d.error); return; }
  const [title, sub] = COPY[d.verdict];
  let html = `<div class="card"><div class="verdict">${gauge(d.score, d.verdict)}
    <div><div class="v-title c-${d.verdict}">${title}</div><p class="v-sub">${sub}</p></div></div>`;

  if (d.extracted_text) {
    html += `<div class="section-h">Text read from screenshot (${esc(d.ocr_engine)})</div><div class="ocr">${esc(d.extracted_text)}</div>`;
  }
  if (d.ai) {
    html += `<div class="section-h">AI second opinion</div><div class="ai-box"><span class="tag">Claude · ${esc(d.ai.verdict)}</span>
      <h4>${esc(d.ai.scam_type && d.ai.scam_type !== "none" ? d.ai.scam_type : "Analysis")}</h4><p>${esc(d.ai.explanation)}</p>
      ${d.ai.tactics.length ? `<div class="sub-h">Tactics used</div><ul>${d.ai.tactics.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}
      ${d.ai.what_to_do.length ? `<div class="sub-h">What to do</div><ul>${d.ai.what_to_do.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}</div>`;
  } else if (d.ai_error) {
    html += `<p class="v-sub gap">${esc(d.ai_error)}</p>`;
  }
  if (d.type === "url" && d.inspection && (d.inspection.fetched || d.inspection.error || d.inspection.chain.length > 1)) {
    html += `<div class="section-h">Where this link really goes</div>` + inspHTML(d.inspection);
  }
  if (d.findings.length) {
    html += `<div class="section-h">${d.type === "url" ? "Why we think so" : "Message red flags"}</div>` + d.findings.map(finding).join("");
  } else if (d.type === "message") {
    html += `<div class="section-h">Message red flags</div><p class="v-sub">No scam phrases detected in the text.</p>`;
  }

  if (d.urls && d.urls.length) {
    html += `<div class="section-h">Links found (${d.urls.length})</div>` + d.urls.map((u) => `
      <details class="urlcard" ${u.verdict !== "safe" ? "open" : ""}>
        <summary><span class="badge b-${u.verdict}">${u.verdict} · ${u.score}</span>${esc(u.input)}</summary>
        ${u.findings.map(finding).join("")}${inspHTML(u.inspection)}
      </details>`).join("");
  }

  if (d.verdict !== "safe") {
    html += `<div class="actions">
      <a class="ghost" href="https://cybercrime.gov.in" target="_blank" rel="noopener">Report at cybercrime.gov.in</a>
      <a class="ghost" href="tel:1930">Call 1930 (India)</a>
      <button class="ghost" id="copy">Copy report</button></div>`;
  }
  html += "</div>";
  out.className = "result"; out.innerHTML = html;

  requestAnimationFrame(() => { const a = $("#arc"); if (a) a.style.strokeDashoffset = a.dataset.target; });
  const cp = $("#copy");
  if (cp) cp.onclick = () => {
    const lines = [`PhishGuard report: ${d.verdict.toUpperCase()} (risk ${d.score}/100)`, `Input: ${input.value.trim()}`, ""]
      .concat(d.findings.map((f) => `- ${f.title}: ${f.detail}`))
      .concat((d.urls || []).flatMap((u) => [`URL ${u.input} -> ${u.verdict} (${u.score})`]));
    navigator.clipboard.writeText(lines.join("\n")).then(() => { cp.textContent = "Copied ✓"; });
  };
  out.scrollIntoView({ behavior: "smooth", block: "start" });
}


// ================= page behaviour =================
root.classList.add("js");

// sticky nav border + mobile menu
const topbar = $("#topbar"), links = $("#links"), burger = $("#burger");
const onScroll = () => topbar.classList.toggle("scrolled", window.scrollY > 8);
window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
burger.onclick = () => { const open = links.classList.toggle("open"); burger.setAttribute("aria-expanded", String(open)); burger.textContent = open ? "Close" : "Menu"; };
links.addEventListener("click", (e) => { if (e.target.tagName === "A") { links.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); burger.textContent = "Menu"; } });

// reveal on scroll
const reveals = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => entries.forEach((en) => {
    if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
  }), { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
  reveals.forEach((el) => io.observe(el));
} else reveals.forEach((el) => el.classList.add("in"));

// count-up numbers
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const counters = document.querySelectorAll("[data-count]");
const countIO = new IntersectionObserver((entries) => entries.forEach((en) => {
  if (!en.isIntersecting) return;
  const el = en.target, end = Number(el.dataset.count);
  countIO.unobserve(el);
  if (reduce) { el.textContent = end; return; }
  const t0 = performance.now(), dur = 1400;
  const tick = (t) => {
    const k = Math.min((t - t0) / dur, 1);
    el.textContent = Math.round(end * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}), { threshold: 0.6 });
counters.forEach((el) => countIO.observe(el));
