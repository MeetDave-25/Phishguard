// Scroll-driven storytelling: maps scroll position inside each pinned section to a 0..1 value (--p)
// that the CSS turns into SVG animation. No libraries.
(() => {
  const root = document.documentElement;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
  const stories = [...document.querySelectorAll("[data-story]")];
  const score = document.getElementById("story-score");

  // split the manifesto into words once
  const scrub = document.querySelector("[data-scrub]");
  let words = [];
  if (scrub) {
    const text = scrub.textContent.trim();
    scrub.textContent = "";
    text.split(/\s+/).forEach((w, i, arr) => {
      const s = document.createElement("span");
      s.className = "w"; s.textContent = w + (i < arr.length - 1 ? " " : "");
      scrub.appendChild(s); words.push(s);
    });
  }

  if (reduce) {
    // static, fully revealed layout
    root.classList.add("static");
    stories.forEach((el) => { el.style.setProperty("--p", "1"); el.dataset.step = "4"; });
    if (score) score.textContent = "91";
    return;
  }

  let ticking = false;
  function update() {
    ticking = false;
    const vh = window.innerHeight;

    stories.forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.bottom < -200 || r.top > vh + 200) return; // off-screen: skip work
      const p = clamp(-r.top / (r.height - vh));
      el.style.setProperty("--p", p.toFixed(4));
      const n = Number(el.dataset.steps) || 1;
      el.dataset.step = String(Math.min(n - 1, Math.floor(p * n)));
    });

    if (score) {
      const sp = Number(score.closest("[data-story]").style.getPropertyValue("--p")) || 0;
      score.textContent = String(Math.round(91 * clamp((sp - 0.62) / 0.14)));
    }

    if (words.length) {
      const rect = scrub.getBoundingClientRect();
      const t = clamp((vh * 0.82 - rect.top) / (vh * 0.5 + rect.height * 0.35));
      const lit = Math.round(t * words.length);
      words.forEach((w, i) => w.classList.toggle("on", i < lit));
    }
  }
  const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll);
  update();
})();
