// Shared on every page: theme, nav, scroll reveal, counters, and OPT-IN analytics consent.
(() => {
  const $ = (s) => document.querySelector(s);
  const root = document.documentElement;
  root.classList.add("js");

  // ---------- theme ----------
  const sysDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  try { root.dataset.theme = localStorage.getItem("theme") || (sysDark ? "dark" : "light"); } catch { root.dataset.theme = sysDark ? "dark" : "light"; }
  const toggleTheme = () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch {}
  };
  const themeBtn = $("#theme");
  if (themeBtn) themeBtn.onclick = toggleTheme;

  // ---------- language menu: close on outside click / Escape ----------
  const langMenu = $("#lang");
  if (langMenu) {
    document.addEventListener("click", (e) => { if (langMenu.open && !langMenu.contains(e.target)) langMenu.open = false; });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && langMenu.open) { langMenu.open = false; langMenu.querySelector("summary").focus(); } });
  }

  // ---------- language preference: remember the choice, switch once on first visit ----------
  const SUPPORTED = ["hi", "gu", "mr", "es"];
  const TRANSLATED_PATHS = ["/", "/contact", "/feedback"];  // pages that exist in every language
  const pageLang = root.lang || "en";
  const getPref = () => { try { return localStorage.getItem("pg_lang"); } catch { return null; } };
  const setPref = (v) => { try { localStorage.setItem("pg_lang", v); } catch {} };
  // an explicit choice in the switcher is remembered (choosing English too, so we never switch away again)
  document.querySelectorAll("#lang a[hreflang], .sheet-langs a[hreflang]").forEach((a) => a.addEventListener("click", () => setPref(a.getAttribute("hreflang"))));
  if (pageLang === "en" && TRANSLATED_PATHS.includes(location.pathname)) {
    let target = getPref();
    let auto = false;
    if (!target) {  // first visit ever: look at the browser's language list, in order; English first means stay
      for (const l of (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "en"])) {
        const code = String(l).toLowerCase().split("-")[0];
        if (code === "en") break;
        if (SUPPORTED.includes(code)) { target = code; auto = true; break; }
      }
    }
    if (target && SUPPORTED.includes(target)) {
      if (auto) { setPref(target); try { sessionStorage.setItem("pg_auto", "1"); } catch {} }
      location.replace("/" + target + location.pathname + location.search + location.hash);
      return;  // the browser is navigating; skip the rest of this page's setup
    }
  }
  // on the page we switched to: say so, and offer the way back
  let switched = false;
  try { switched = sessionStorage.getItem("pg_auto") === "1"; sessionStorage.removeItem("pg_auto"); } catch {}
  const showSwitchedNotice = () => {
    let I = {};
    try { I = JSON.parse(document.getElementById("i18n").textContent); } catch {}
    const nameEl = document.querySelector("#lang summary span");
    if (I.auto_switched) {
      const t = document.createElement("div");
      t.className = "toast"; t.setAttribute("role", "status");
      const msg = document.createElement("span"); msg.textContent = I.auto_switched.replace("{lang}", nameEl ? nameEl.textContent : pageLang);
      const back = document.createElement("a"); back.href = location.pathname.replace(/^\/[a-z]{2}(?=\/|$)/, "") || "/"; back.setAttribute("hreflang", "en"); back.textContent = I.auto_back;
      back.addEventListener("click", () => setPref("en"));
      const x = document.createElement("button"); x.type = "button"; x.setAttribute("aria-label", "×"); x.textContent = "×"; x.onclick = () => t.remove();
      t.append(msg, back, x); document.body.appendChild(t);
      setTimeout(() => t.remove(), 12000);
    }
  };
  // the language data block comes after this script in the page, so wait for the document to finish parsing
  if (switched && pageLang !== "en") { if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", showSwitchedNotice); else showSwitchedNotice(); }

  // ---------- sticky nav border + mobile menu ----------
  const topbar = $("#topbar"), links = $("#links"), burger = $("#burger");
  if (topbar) {
    const onScroll = () => topbar.classList.toggle("scrolled", window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  }
  if (burger && links) {
    burger.onclick = () => { const open = links.classList.toggle("open"); burger.setAttribute("aria-expanded", String(open)); burger.textContent = open ? "Close" : "Menu"; };
    links.addEventListener("click", (e) => { if (e.target.tagName === "A") { links.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); burger.textContent = "Menu"; } });
  }

  // ---------- reveal on scroll ----------
  const reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => entries.forEach((en) => {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    }), { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
    reveals.forEach((el) => io.observe(el));
  } else reveals.forEach((el) => el.classList.add("in"));

  // ---------- count-up numbers ----------
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const counters = document.querySelectorAll("[data-count]");
  if (counters.length && "IntersectionObserver" in window) {
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
  } else counters.forEach((el) => { el.textContent = el.dataset.count; });

  // ---------- mobile app chrome: bottom tab bar, "More" sheet, install, offline ----------
  const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  if (standalone) root.classList.add("standalone");

  const sheet = $("#sheet"), sheetBg = $("#sheet-bg"), moreBtn = $("#more-btn");
  function setSheet(open) {
    if (!sheet) return;
    sheet.classList.toggle("open", open); sheetBg.classList.toggle("open", open);
    sheet.setAttribute("aria-hidden", String(!open)); sheet.inert = !open;
    moreBtn.setAttribute("aria-expanded", String(open));
    document.body.classList.toggle("no-scroll", open);
    if (open) { const f = sheet.querySelector("a,button:not([hidden])"); if (f) f.focus(); } else moreBtn.focus({ preventScroll: true });
  }
  if (sheet && moreBtn) {
    sheet.inert = true;
    moreBtn.onclick = () => setSheet(!sheet.classList.contains("open"));
    sheetBg.onclick = () => setSheet(false);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && sheet.classList.contains("open")) setSheet(false); });
    sheet.addEventListener("click", (e) => { const t = e.target.closest("a,button"); if (t && t.id !== "theme-sheet" && t.id !== "install-btn") setSheet(false); });
    const themeSheet = $("#theme-sheet"); if (themeSheet) themeSheet.onclick = toggleTheme;
  }

  // highlight "Check" while the checker is on screen; tapping it jumps there and opens the keyboard
  const checkSec = $("#checker"), tabHome = $('.tabbar [data-tab="home"]'), tabCheck = $('.tabbar [data-tab="check"]');
  if (checkSec && tabCheck && "IntersectionObserver" in window) {
    // the checker section can be taller than the screen (it grows when a result is shown), so measure visible HEIGHT, not a ratio
    new IntersectionObserver((es) => es.forEach((en) => {
      const on = en.isIntersecting && en.intersectionRect.height > window.innerHeight * 0.35;
      tabCheck.classList.toggle("on", on);
      if (tabHome) { if (on) tabHome.removeAttribute("aria-current"); else tabHome.setAttribute("aria-current", "page"); }
    }), { threshold: [0, 0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1] }).observe(checkSec);
  }
  if (tabCheck && checkSec) tabCheck.addEventListener("click", (e) => {
    e.preventDefault();
    checkSec.scrollIntoView({ behavior: "smooth", block: "start" });
    setTimeout(() => { const i = $("#input"); if (i) i.focus({ preventScroll: true }); }, 450);
  });

  // install as an app (Android/desktop Chrome); iPhone gets instructions
  let deferredInstall = null;
  const installBtn = $("#install-btn"), iosHint = $("#ios-hint");
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); deferredInstall = e; if (installBtn) installBtn.hidden = false; });
  window.addEventListener("appinstalled", () => { if (installBtn) installBtn.hidden = true; });
  if (installBtn) installBtn.onclick = async () => { if (!deferredInstall) return; deferredInstall.prompt(); await deferredInstall.userChoice; deferredInstall = null; installBtn.hidden = true; setSheet(false); };
  if (iosHint && /iphone|ipad|ipod/i.test(navigator.userAgent) && !standalone) iosHint.hidden = false;

  // service worker: installable + offline page + "Share to PhishGuard" (caches only the site's own files)
  if ("serviceWorker" in navigator) window.addEventListener("load", () => { navigator.serviceWorker.register("/sw.js").catch(() => {}); });

  // ---------- analytics consent (only active when the server was configured with Google IDs) ----------
  const meta = (n) => (document.querySelector('meta[name="' + n + '"]') || {}).content || "";
  const GA = meta("pg-ga"), ADS = meta("pg-ads"), CONV = meta("pg-ads-conv");
  if (!GA && !ADS) return; // nothing configured: this site loads nothing from Google, and shows no banner

  const KEY = "pg_consent";
  const getConsent = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  const setConsent = (v) => { try { localStorage.setItem(KEY, v); } catch {} };
  let loaded = false;

  function loadGoogle() {
    if (loaded) return;
    loaded = true;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    // Consent Mode v2: start denied, then grant exactly what the visitor accepted.
    window.gtag("consent", "default", { ad_storage: "denied", analytics_storage: "denied", ad_user_data: "denied", ad_personalization: "denied" });
    window.gtag("js", new Date());
    const s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(GA || ADS);
    document.head.appendChild(s);
    window.gtag("consent", "update", {
      analytics_storage: GA ? "granted" : "denied",
      ad_storage: ADS ? "granted" : "denied", ad_user_data: ADS ? "granted" : "denied", ad_personalization: ADS ? "granted" : "denied",
    });
    if (GA) window.gtag("config", GA);
    if (ADS) window.gtag("config", ADS);
    // Count a lead only on the thank-you page reached through a real, signed form submission.
    if (document.body.dataset.conv === "1") {
      if (GA) window.gtag("event", "generate_lead");
      if (ADS && CONV) window.gtag("event", "conversion", { send_to: ADS + "/" + CONV });
    }
  }

  function clearGoogleCookies() {
    const host = location.hostname, parts = host.split(".");
    const domains = [host, "." + host]; if (parts.length > 2) domains.push("." + parts.slice(-2).join("."));
    document.cookie.split(";").forEach((c) => {
      const name = c.split("=")[0].trim();
      if (/^(_ga|_gid|_gat|_gcl)/.test(name)) domains.forEach((d) => { document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=" + d; document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"; });
    });
  }

  function closeBanner() { const b = $("#consent"); if (b) b.remove(); }
  function openBanner() {
    if ($("#consent")) return;
    const b = document.createElement("div");
    b.id = "consent"; b.className = "consent"; b.setAttribute("role", "dialog"); b.setAttribute("aria-label", "Cookie preferences");
    const p = document.createElement("p");
    p.append("We’d like to use Google Analytics" + (ADS ? " and Google Ads measurement" : "") + " to understand how this site is used. They set cookies and send data to Google. Nothing loads unless you accept. ");
    const a = document.createElement("a"); a.href = "/cookies"; a.textContent = "Cookie policy"; p.append(a);
    const row = document.createElement("div"); row.className = "consent-row";
    const no = document.createElement("button"); no.type = "button"; no.className = "ghost"; no.textContent = "Decline";
    const yes = document.createElement("button"); yes.type = "button"; yes.className = "btn btn-sm"; yes.textContent = "Accept";
    no.onclick = () => { setConsent("denied"); if (loaded && window.gtag) { window.gtag("consent", "update", { analytics_storage: "denied", ad_storage: "denied", ad_user_data: "denied", ad_personalization: "denied" }); } clearGoogleCookies(); closeBanner(); };
    yes.onclick = () => { setConsent("granted"); closeBanner(); loadGoogle(); };
    row.append(no, yes); b.append(p, row);
    document.body.appendChild(b);
  }

  document.querySelectorAll("[data-consent-open]").forEach((el) => el.addEventListener("click", openBanner));
  const c = getConsent();
  if (c === "granted") loadGoogle();
  else if (c !== "denied") openBanner();
})();
