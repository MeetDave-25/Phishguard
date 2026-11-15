const $ = (s) => document.querySelector(s);
const input = $("#input"), go = $("#go"), out = $("#result"), live = $("#live"), aiBox = $("#ai"), inspect = $("#inspect"), drop = $("#drop"), fileIn = $("#file");
let image = null;

// Language bundle rendered by the server (<script type="application/json" id="i18n">) + the page language.
const LANG = document.documentElement.lang || "en";
let I = {};
try { I = JSON.parse(document.getElementById("i18n").textContent); } catch {}
const fmt = (s, o) => String(s).replace(/\{(\w+)\}/g, (m, k) => (o && o[k] !== undefined ? o[k] : m));

document.querySelectorAll(".chip").forEach((c) => (c.onclick = () => { input.value = c.dataset.example; run(); }));
input.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });
go.onclick = run;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const COPY = {
  safe: [I.safe_t, I.safe_s],
  suspicious: [I.warn_t, I.warn_s],
  dangerous: [I.bad_t, I.bad_s],
};
const VERDICT_WORD = { safe: I.v_safe, suspicious: I.v_susp, dangerous: I.v_bad };
const COLOR = { safe: "#22c55e", suspicious: "#f59e0b", dangerous: "#ff4a1c" };

fetch("/api/status").then((r) => r.json()).then((st) => {
  if (st.ai) { aiBox.disabled = false; aiBox.checked = true; $("#ai-note").textContent = I.ai_note; }
  else $("#ai-toggle").style.display = "none";
  const dot = (on, t) => `<span class="${on ? "on" : ""}"><i></i>${t}</span>`;
  $("#intel").innerHTML = dot(st.openphish, I.chip_openphish) + dot(st.dns, I.chip_dns) + dot(st.safe_browsing, I.chip_gsb) + dot(st.ocr, I.chip_ocr);
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
  go.innerHTML = '<span class="spinner"></span> ' + I.analyzing;
  try {
    let r;
    if (image && !value) {
      const fd = new FormData();
      fd.append("image", image); fd.append("live", live.checked ? "1" : "0"); fd.append("ai", aiBox.checked ? "1" : "0"); fd.append("inspect", inspect.checked ? "1" : "0"); fd.append("lang", LANG);
      r = await fetch("/api/analyze-image", { method: "POST", body: fd });
    } else {
      r = await fetch("/api/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: value, live: live.checked, ai: aiBox.checked, inspect: inspect.checked, lang: LANG }),
      });
    }
    render(await r.json());
  } catch (e) {
    out.className = "result card"; out.innerHTML = I.error;
  } finally {
    go.disabled = false;
    go.innerHTML = esc(I.analyze) + ' <span class="kbd">Ctrl ↵</span>';
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
    h += `<p class="v-sub gap">${esc(I.page_title)} <b>${esc(ins.title || I.none)}</b> · ${esc(ins.forms === 1 ? I.forms_one : fmt(I.forms_n, { n: ins.forms }))}${ins.has_password ? " · " + esc(I.asks_pw) : ""}</p>`;
  } else if (ins.error) {
    h += `<p class="v-sub gap">${esc(fmt(I.not_inspected, { err: ins.error }))}</p>`;
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
    <div class="num"><div>${score}<small>${esc(I.risk)}</small></div></div></div>`;
}

function render(d) {
  if (d.error) { out.className = "result card"; out.innerHTML = esc(d.error); return; }
  const [title, sub] = COPY[d.verdict];
  let html = `<div class="card"><div class="verdict">${gauge(d.score, d.verdict)}
    <div><div class="v-title c-${d.verdict}">${esc(title)}</div><p class="v-sub">${esc(sub)}</p></div></div>`;

  if (d.qr && d.qr.length) {
    html += `<div class="section-h">${esc(I.qr_h)}</div><div class="ocr">${d.qr.map(esc).join("\n")}</div>`;
  }
  if (d.extracted_text && !(d.qr && d.qr.length && d.ocr_engine === "qr")) {
    html += `<div class="section-h">${esc(fmt(I.ocr_h, { engine: d.ocr_engine }))}</div><div class="ocr">${esc(d.extracted_text)}</div>`;
  }
  if (d.ai) {
    html += `<div class="section-h">${esc(I.ai_h)}</div><div class="ai-box"><span class="tag">Claude · ${esc(d.ai.verdict)}</span>
      <h4>${esc(d.ai.scam_type && d.ai.scam_type !== "none" ? d.ai.scam_type : I.analysis)}</h4><p>${esc(d.ai.explanation)}</p>
      ${d.ai.tactics.length ? `<div class="sub-h">${esc(I.tactics)}</div><ul>${d.ai.tactics.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}
      ${d.ai.what_to_do.length ? `<div class="sub-h">${esc(I.todo)}</div><ul>${d.ai.what_to_do.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}</div>`;
  } else if (d.ai_error) {
    html += `<p class="v-sub gap">${esc(d.ai_error)}</p>`;
  }
  if (d.type === "url" && d.inspection && (d.inspection.fetched || d.inspection.error || d.inspection.chain.length > 1)) {
    html += `<div class="section-h">${esc(I.where)}</div>` + inspHTML(d.inspection);
  }
  if (d.findings.length) {
    html += `<div class="section-h">${esc(d.type === "url" ? I.why : I.flags)}</div>` + d.findings.map(finding).join("");
  } else if (d.type === "message") {
    html += `<div class="section-h">${esc(I.flags)}</div><p class="v-sub">${esc(I.no_phrases)}</p>`;
  }

  if (d.urls && d.urls.length) {
    html += `<div class="section-h">${esc(fmt(I.links, { n: d.urls.length }))}</div>` + d.urls.map((u) => `
      <details class="urlcard" ${u.verdict !== "safe" ? "open" : ""}>
        <summary><span class="badge b-${u.verdict}">${esc(VERDICT_WORD[u.verdict])} · ${u.score}</span>${esc(u.input)}</summary>
        ${u.findings.map(finding).join("")}${inspHTML(u.inspection)}
      </details>`).join("");
  }

  if (d.verdict !== "safe") {
    html += `<div class="actions">
      <a class="ghost" href="${esc(I.report_href)}" target="_blank" rel="noopener">${esc(I.report)}</a>
      <a class="ghost" href="${esc(I.call_href)}">${esc(I.call)}</a>
      <button class="ghost" id="copy">${esc(I.copy)}</button></div>`;
  }
  html += "</div>";
  out.className = "result"; out.innerHTML = html;

  requestAnimationFrame(() => { const a = $("#arc"); if (a) a.style.strokeDashoffset = a.dataset.target; });
  const cp = $("#copy");
  if (cp) cp.onclick = () => {
    const lines = [fmt(I.report_title, { verdict: VERDICT_WORD[d.verdict].toUpperCase(), score: d.score }), `${I.report_input} ${input.value.trim()}`, ""]
      .concat(d.findings.map((f) => `- ${f.title}: ${f.detail}`))
      .concat((d.urls || []).flatMap((u) => [`URL ${u.input} -> ${VERDICT_WORD[u.verdict]} (${u.score})`]));
    navigator.clipboard.writeText(lines.join("\n")).then(() => { cp.textContent = I.copied; });
  };
  out.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Text shared from another app ("Share to PhishGuard"). The service worker stored it in the browser only.
(async () => {
  if (new URLSearchParams(location.search).get("shared") !== "1") return;
  try {
    if ("caches" in window) {
      const c = await caches.open("pg-share");
      const r = await c.match("/__shared");
      if (r) {
        const t = (await r.text()).trim();
        await c.delete("/__shared");
        if (t) { input.value = t.slice(0, 5000); run(); }
      }
    }
  } catch {}
  history.replaceState(null, "", location.pathname + "#checker");
})();

// phones: the whole screenshot box opens the photo picker
drop.addEventListener("click", (e) => { if (!e.target.closest("label")) fileIn.click(); });
