// FinishUP particle artwork: a few thousand points that rearrange, like atoms, into
// each scene of the story (the words agents do, a clock, a swarm of agents, a robot that
// fades and is checked back to green, a sun that rises with the score, the lockup). The
// page tells the engine which scene is in view and how far through it the reader is; the
// engine does the rest on a 2D canvas with a light 3D projection.

const PALETTE = {
  particle: "#064E3B",
  signal: "#10B981",
  faint: "#8FA39B",
  silver: "#73858F",
  gold: "#C48A0E",
};

const HERO_WORDS = ["work", "code", "research", "science", "writing", "reviews"];
const HERO_SECONDS = 3.2;
const SCENE_OFFSETS = new Map([["alone", -0.08], ["swarm", -0.08], ["robot", -0.12], ["sun", -0.1]]);
// once the reader starts scrolling, the hero keeps the word it was showing
const HERO_HOLD_AT = 0.56;

// The scroll story, in screens. Around each boundary the two neighbouring shapes are
// blended by scroll position (BLEND screens either side), so the dots move with the
// reader's hand rather than racing to a new shape when a line is crossed. The page passes
// its own plan; this one is the fallback.
const PLAN = [["hero", 0.82], ["alone", 1.5], ["swarm", 1.5], ["robot", 3.6], ["sun", 3], ["end", 1]];
const BLEND = 0.3;
const clamp01 = (v) => Math.max(0, Math.min(1, v));
// The benchmark count-up takes at most this many steps, so it samples a bounded set of figures.
const COUNT_STEPS = 40;
const decimalsOf = (figure) => (/\.(\d+)$/.exec(String(figure).trim()) || ["", ""])[1].length;
const smooth = (v) => { const u = clamp01(v); return u * u * (3 - 2 * u); };
function timeline(s, plan) {
  let acc = 0;
  for (let i = 0; i < plan.length; i++) {
    const [name, len] = plan[i];
    const end = acc + len;
    if (s < end || i === plan.length - 1) {
      const pa = clamp01((s - acc) / len);
      if (i < plan.length - 1 && s > end - BLEND) {
        return { a: name, ia: i, pa, b: plan[i + 1][0], ib: i + 1, pb: clamp01((s - end) / plan[i + 1][1]), u: smooth((s - (end - BLEND)) / (2 * BLEND)) };
      }
      if (i > 0 && s < acc + BLEND) {
        return { a: plan[i - 1][0], ia: i - 1, pa: 1, b: name, ib: i, pb: pa, u: smooth((s - (acc - BLEND)) / (2 * BLEND)) };
      }
      return { a: name, ia: i, pa, b: null, ib: -1, pb: 0, u: 0 };
    }
    acc = end;
  }
  return { a: "end", ia: plan.length - 1, pa: 1, b: null, ib: -1, pb: 0, u: 0 };
}

export function mountParticles(canvas, options = {}) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return { setScene() {}, setScroll() {}, setAnchor() {}, setTier() {}, destroy() {} };
  const reduced = !!options.reducedMotion;
  const N = Math.max(800, Math.min(9000, options.count || 9000));
  const sun = options.sun || "#E9B200";
  // Scores are evidence supplied by the caller, never an artwork default.
  const scores = options.scores || [];
  const drawTier = options.drawTier !== false;
  const plan = options.plan && options.plan.length ? options.plan : PLAN;

  const pos = new Float32Array(N * 3);
  const vel = new Float32Array(N * 3);
  const tgt = new Float32Array(N * 3);
  const tgtA = new Float32Array(N * 3);
  const tcolA = new Uint8Array(N);
  const col = new Uint8Array(N);
  const tcol = new Uint8Array(N);
  const px = new Float32Array(N);
  const py = new Float32Array(N);
  const ps = new Float32Array(N);
  const big = new Float32Array(N); // dot size multiplier: the benchmark's figures and words keep larger dots
  const tbig = new Float32Array(N);
  const pa = new Float32Array(N);
  const R = new Float32Array(N * 6);
  big.fill(1);
  tbig.fill(1);

  let seed = 20260603;
  for (let i = 0; i < N * 6; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    R[i] = seed / 4294967296;
  }
  for (let i = 0; i < N; i++) {
    pos[i * 3] = (R[i * 6] - 0.5) * 3.2;
    pos[i * 3 + 1] = (R[i * 6 + 1] - 0.5) * 3.2;
    pos[i * 3 + 2] = (R[i * 6 + 2] - 0.5) * 3.2;
  }
  // A faint haze of dots behind everything, drifting slowly, that the shapes seem to
  // gather from and dissolve back into.
  const BG = Math.round(N * 0.5);
  const bg = new Float32Array(BG * 4);
  for (let i = 0; i < BG; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; const a = seed / 4294967296;
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; const b = seed / 4294967296;
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; const c = seed / 4294967296;
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; const d = seed / 4294967296;
    bg[i * 4] = (a - 0.5) * 3.4;
    bg[i * 4 + 1] = (b - 0.5) * 2.4;
    bg[i * 4 + 2] = 0.4 + c * 1.2;
    bg[i * 4 + 3] = d * 6.2832;
  }

  let cache = {};
  const off = document.createElement("canvas");
  off.width = 900;
  off.height = 300;
  const offCtx = off.getContext("2d", { willReadFrequently: true });
  // one soft round dot per colour, stamped for every point
  const sprites = {};
  const sprite = (color) => {
    if (sprites[color]) return sprites[color];
    const c = document.createElement("canvas");
    c.width = c.height = 24;
    const g = c.getContext("2d");
    g.fillStyle = color;
    g.beginPath();
    g.arc(12, 12, 11, 0, 6.2832);
    g.fill();
    return (sprites[color] = c);
  };

  let scene = { form: "hero", phase: 0 };
  let scroll = null; // screens into the story, when the page drives the engine by scroll
  let anchor = null; // canvas-pixel position of the word "computer" in the closing copy
  let anchorN = { x: 0.32, y: 0.52 };
  let tierPx = null; // the slot in the copy where the tier word is drawn in dots
  let narrowLayout = false; // phone: artwork up top, score above the sun
  const defaultTier = { x: 0.9, y: 0.55, w: 0.7, h: 0.3 };
  let tierN = defaultTier;
  let scoreRoom = Infinity; // scene units left of the camera centre the side score may use
  let tilt = 0;
  let ox = 0;
  let orb = 0;
  let jit = reduced ? 0 : 0.5;
  let scaleS = 400; // the last frame's scale, canvas px per unit
  let mx = 0;
  let smx = 0;
  let heroWord = 0;
  let visible = typeof IntersectionObserver === "undefined";
  let destroyed = false;
  let dirty = true;
  let raf = 0;
  let elapsed = 0;
  let lastTime = null;

  const set = (i, x, y, z, c) => {
    tgt[i * 3] = x;
    tgt[i * 3 + 1] = y;
    tgt[i * 3 + 2] = z;
    tcol[i] = c;
    tbig[i] = 1;
  };
  const scatter = (i) => set(i, (R[i * 6] - 0.5) * 2.8, (R[i * 6 + 1] - 0.5) * 2.8, (R[i * 6 + 2] - 0.5) * 2.8, 4);
  // Each dot takes the sample point at its own place in the shape's angular order, so dots
  // that are neighbours in one shape stay neighbours in the next and the change flows rather
  // than scattering. Solid shapes get a front and a back face, as deep as the shape is
  // thick, so they read as volumes when the camera turns; `flat` keeps them on the plane.
  const fromSet = (i, pts, sc, dx, dy, zj, c, flat) => {
    const n = pts.length / 3;
    if (!n) return scatter(i);
    const idx = pts.order[Math.min(n - 1, Math.floor(R[i * 6] * n))];
    const j = idx * 3;
    let z;
    if (flat) z = (R[i * 6 + 4] - 0.5) * zj;
    else {
      const zh = Math.min(0.08, pts.dep[idx] * 0.8 + 0.01);
      z = (R[i * 6 + 4] < 0.5 ? -1 : 1) * zh * Math.min(sc, 1.2) * (0.8 + R[i * 6 + 2] * 0.2);
    }
    set(i, pts[j] * sc + dx, pts[j + 1] * sc + dy, z, c == null ? (pts[j + 2] ? 1 : 0) : c);
  };
  // like fromSet, but points i0..i1 walk the sample in order, so coverage is even and
  // the letters read crisply (no clumps, no gaps, no depth jitter)
  const fromSetEven = (i, i0, i1, pts, sc, dx, dy, c) => {
    const n = pts.length / 3;
    if (!n) return scatter(i);
    const j = Math.min(n - 1, Math.floor(((i - i0) / Math.max(1, i1 - i0)) * n)) * 3;
    set(i, pts[j] * sc + dx, pts[j + 1] * sc + dy, 0, c);
  };
  const sphere = (i, cx, cy, cz, r, c) => {
    const u = R[i * 6] * 2 - 1;
    const ph = R[i * 6 + 1] * 6.2832;
    const rr = r * Math.cbrt(R[i * 6 + 2]);
    const q = Math.sqrt(1 - u * u);
    set(i, cx + rr * q * Math.cos(ph), cy + rr * q * Math.sin(ph), cz + rr * u, c);
  };
  // a ring with a rim: two faces a little apart, like the edge of a dial
  const ring = (i, cx, cy, r, w, c) => {
    const a = R[i * 6] * 6.2832;
    const rr = r + (R[i * 6 + 1] - 0.5) * w;
    set(i, cx + rr * Math.cos(a), cy + rr * Math.sin(a), (R[i * 6 + 2] < 0.5 ? -1 : 1) * 0.05 + (R[i * 6 + 3] - 0.5) * 0.03, c);
  };
  const seg = (i, x1, y1, x2, y2, w, c, z) => {
    const u = R[i * 6];
    const o = (R[i * 6 + 1] - 0.5) * w;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const L = Math.hypot(dx, dy) || 1;
    set(i, x1 + dx * u - (dy / L) * o, y1 + dy * u + (dx / L) * o, (z || 0) + (R[i * 6 + 2] - 0.5) * 0.05, c);
  };
  const clock = (i, f, cx, cy, r, hA, mA) => {
    if (f < 0.56) ring(i, cx, cy, r, r * 0.07, 0);
    else if (f < 0.72) {
      const k = Math.floor(R[i * 6 + 5] * 12);
      const a = (k / 12) * 6.2832;
      seg(i, cx + Math.cos(a) * r * 0.84, cy + Math.sin(a) * r * 0.84, cx + Math.cos(a) * r * 0.91, cy + Math.sin(a) * r * 0.91, r * 0.035, 0);
    } else if (f < 0.85) seg(i, cx, cy, cx + Math.cos(hA) * r * 0.5, cy + Math.sin(hA) * r * 0.5, r * 0.07, 0);
    else seg(i, cx, cy, cx + Math.cos(mA) * r * 0.78, cy + Math.sin(mA) * r * 0.78, r * 0.045, 0);
  };
  // A laptop the size of a word, drawn where the closing copy says "computer".
  const laptop = (i, f, ax, ay, s, c) => {
    const w = 0.5 * s, h = 0.34 * s;
    const q = (f * 5) | 0;
    if (q === 0) seg(i, ax - w, ay - h, ax + w, ay - h, 0.03 * s, c);
    else if (q === 1) seg(i, ax + w, ay - h, ax + w, ay + h * 0.75, 0.03 * s, c);
    else if (q === 2) seg(i, ax - w, ay + h * 0.75, ax - w, ay - h, 0.03 * s, c);
    else if (q === 3) seg(i, ax - w, ay + h * 0.75, ax + w, ay + h * 0.75, 0.03 * s, c);
    else seg(i, ax - w * 1.25, ay + h, ax + w * 1.25, ay + h, 0.05 * s, c);
  };
  void laptop;

  function sample(key, draw) {
    if (cache[key]) return cache[key];
    const W = off.width;
    const H = off.height;
    const c = offCtx;
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.clearRect(0, 0, W, H);
    draw(c, W, H);
    const d = c.getImageData(0, 0, W, H).data;
    // distance from each sample to the shape's edge (two-pass chamfer on the sampling grid):
    // how thick the shape is there, so it can be given volume
    const gw = W / 2, gh = H / 2;
    const dist = new Float32Array(gw * gh);
    for (let gy = 0; gy < gh; gy++) for (let gx = 0; gx < gw; gx++) dist[gy * gw + gx] = d[(gy * 2 * W + gx * 2) * 4 + 3] > 120 ? 1e6 : 0;
    for (let gy = 0; gy < gh; gy++) {
      for (let gx = 0; gx < gw; gx++) {
        const q = gy * gw + gx;
        let v = dist[q];
        if (!v) continue;
        v = Math.min(v, gx > 0 ? dist[q - 1] + 1 : 1);
        if (gy > 0) {
          v = Math.min(v, dist[q - gw] + 1);
          if (gx > 0) v = Math.min(v, dist[q - gw - 1] + 1.414);
          if (gx < gw - 1) v = Math.min(v, dist[q - gw + 1] + 1.414);
        } else v = Math.min(v, 1);
        dist[q] = v;
      }
    }
    for (let gy = gh - 1; gy >= 0; gy--) {
      for (let gx = gw - 1; gx >= 0; gx--) {
        const q = gy * gw + gx;
        let v = dist[q];
        if (!v) continue;
        v = Math.min(v, gx < gw - 1 ? dist[q + 1] + 1 : 1);
        if (gy < gh - 1) {
          v = Math.min(v, dist[q + gw] + 1);
          if (gx < gw - 1) v = Math.min(v, dist[q + gw + 1] + 1.414);
          if (gx > 0) v = Math.min(v, dist[q + gw - 1] + 1.414);
        } else v = Math.min(v, 1);
        dist[q] = v;
      }
    }
    const pts = [];
    const dep = [];
    for (let gy = 0; gy < gh; gy++) {
      for (let gx = 0; gx < gw; gx++) {
        const k = (gy * 2 * W + gx * 2) * 4;
        if (d[k + 3] > 120) {
          pts.push((gx * 2 - W / 2) / (W / 2), (gy * 2 - H / 2) / (W / 2), d[k + 1] > 128 ? 1 : 0);
          dep.push((dist[gy * gw + gx] * 2) / (W / 2));
        }
      }
    }
    const n = pts.length / 3;
    let lo = 9, hi = -9, mx0 = 0, my0 = 0;
    for (let j = 0; j < n; j++) {
      const x = pts[j * 3];
      if (x < lo) lo = x;
      if (x > hi) hi = x;
      mx0 += x;
      my0 += pts[j * 3 + 1];
    }
    mx0 /= Math.max(1, n);
    my0 /= Math.max(1, n);
    // the samples in angular order around the shape's centre (see fromSet)
    const ang = new Float32Array(n);
    for (let j = 0; j < n; j++) {
      let a = Math.atan2(pts[j * 3 + 1] - my0, pts[j * 3] - mx0);
      if (a < 0) a += 6.2832;
      ang[j] = a;
    }
    const order = new Uint32Array(n);
    for (let j = 0; j < n; j++) order[j] = j;
    order.sort((p, q) => ang[p] - ang[q]);
    pts.width = Math.max(0.2, hi - lo);
    pts.lo = lo;
    pts.hi = hi;
    pts.dep = dep;
    pts.order = order;
    cache[key] = pts;
    return pts;
  }
  const wordSet = (w, heavy) =>
    sample((heavy ? "W:" : "w:") + w, (c, W, H) => {
      let size = 200;
      c.font = `600 ${size}px "Geist", system-ui, sans-serif`;
      const m = c.measureText(w).width;
      if (m > 800) {
        size = Math.floor((size * 800) / m);
        c.font = `600 ${size}px "Geist", system-ui, sans-serif`;
      }
      c.textAlign = "center";
      c.textBaseline = "middle";
      c.fillStyle = "#000";
      c.fillText(w, W / 2, H / 2 + 4);
      if (heavy) {
        c.strokeStyle = "#000";
        c.lineWidth = size * 0.07;
        c.lineJoin = "round";
        c.strokeText(w, W / 2, H / 2 + 4);
      }
    });
  const logoSet = () =>
    sample("logo", (c) => {
      const x = 50, y = 95, w = 140, h = 140, r = 26;
      c.lineCap = "round";
      c.lineJoin = "round";
      c.strokeStyle = "#000";
      c.lineWidth = 32;
      c.beginPath();
      c.moveTo(x + w, y + 70);
      c.arcTo(x + w, y + h, x, y + h, r);
      c.arcTo(x, y + h, x, y, r);
      c.arcTo(x, y, x + w, y, r);
      c.lineTo(x + w - 58, y);
      c.stroke();
      c.strokeStyle = "#00ff00";
      c.lineWidth = 28;
      c.beginPath();
      c.moveTo(x + 92, y + 12);
      c.lineTo(x + 124, y + 46);
      c.lineTo(x + 196, y - 30);
      c.stroke();
      c.font = '600 128px "Geist", system-ui, sans-serif';
      c.textAlign = "left";
      c.textBaseline = "middle";
      c.fillStyle = "#000";
      c.fillText("FinishUP", 280, 168);
    });
  const figureSet = () =>
    sample("figure", (c, W, H) => {
      const cx = W / 2, cy = H / 2;
      c.fillStyle = "#000";
      c.beginPath();
      c.arc(cx, cy - 78, 34, 0, 6.3);
      c.fill();
      c.fillRect(cx - 11, cy - 46, 22, 22);
      c.beginPath();
      c.moveTo(cx - 62, cy - 10);
      c.quadraticCurveTo(cx, cy - 44, cx + 62, cy - 10);
      c.lineTo(cx + 74, cy + 118);
      c.lineTo(cx - 74, cy + 118);
      c.closePath();
      c.fill();
    });
  const rrect = (c, x, y, w, h, r) => {
    c.beginPath();
    c.moveTo(x + r, y);
    c.arcTo(x + w, y, x + w, y + h, r);
    c.arcTo(x + w, y + h, x, y + h, r);
    c.arcTo(x, y + h, x, y, r);
    c.arcTo(x, y, x + w, y, r);
    c.closePath();
    c.fill();
  };
  const robotSet = () =>
    sample("robot", (c, W) => {
      const cx = W / 2;
      c.fillStyle = "#000";
      c.beginPath();
      c.arc(cx, 34, 9, 0, 6.3);
      c.fill();
      c.fillRect(cx - 3, 40, 6, 16);
      rrect(c, cx - 56, 56, 112, 86, 18);
      c.clearRect(cx - 34, 84, 24, 20);
      c.clearRect(cx + 10, 84, 24, 20);
      c.fillRect(cx - 10, 142, 20, 14);
      rrect(c, cx - 66, 156, 132, 108, 16);
      rrect(c, cx - 104, 166, 30, 82, 12);
      rrect(c, cx + 74, 166, 30, 82, 12);
    });

  // `idx` is the scene's place in the plan; `phase` how far through it the reader is.
  function build(name, t, phase, idx) {
    // orbit: how far the camera has turned with the scroll; still: the scene holds
    // perfectly still once formed (the closing lockup)
    const spec = { tilt: 0, ox: SCENE_OFFSETS.get(name) || 0, yawAmp: 0.26, orbit: 0, mouse: true, still: false, turn: true };
    let pts, i, f, k, a;
    switch (name) {
      case "logo":
      case "end": {
        // The lockup in the top third, clear of the closing copy, and then frozen: it stays
        // exactly as drawn while the page scrolls on to the footer.
        pts = logoSet();
        spec.yawAmp = 0;
        spec.mouse = false;
        spec.still = true;
        spec.turn = false;
        const ly = narrowLayout ? -0.62 : -0.7;
        for (i = 0; i < N; i++) {
          f = i / N;
          if (f < 0.96) fromSet(i, pts, 0.56, 0, ly, 0.04, null, true);
          else sphere(i, 0, ly, 0, 0.8, 1);
        }
        break;
      }
      case "alone": {
        // the clock's hands follow the scroll: an hour and a half passes in this scene
        pts = figureSet();
        const hA = -1.5708 + phase * 0.9;
        const mA = -1.5708 + phase * 9.4248;
        for (i = 0; i < N; i++) {
          f = i / N;
          if (f < 0.3) fromSet(i, pts, 1.1, -0.58, 0.04, 0.12, 0);
          else clock(i, (f - 0.3) / 0.7, 0.36, 0, 0.44, hA, mA);
        }
        break;
      }
      case "swarm": {
        // small robots on a tilted orbit around the human, clear of the copy on the right;
        // the clock, shrunk, now races: six turns of the minute hand across the scene
        pts = figureSet();
        const bots = robotSet();
        const hA = -1.5708 + 0.9 + phase * 3;
        const mA = -1.5708 + 9.4248 + phase * 37.7;
        for (i = 0; i < N; i++) {
          f = i / N;
          if (f < 0.3) fromSet(i, pts, 1.05, 0, 0.02, 0.12, 0);
          else if (f < 0.46) clock(i, (f - 0.3) / 0.16, 0.7, -0.5, 0.18, hA, mA);
          else {
            k = Math.floor(((f - 0.46) / 0.54) * 6);
            a = (k / 6) * 6.2832 + t * 0.35;
            fromSet(i, bots, 0.44, Math.cos(a) * 0.52, Math.sin(a) * 0.42 + 0.02, 0.1, R[i * 6 + 5] < 0.06 ? 1 : 0);
            tgt[i * 3 + 2] += Math.sin(a) * 0.4;
          }
        }
        break;
      }
      case "robot": {
        // One scene over three beats: the agent fades, FinishUP's check arrives, the agent
        // comes back greener than it started.
        pts = robotSet();
        spec.yawAmp = 0.2;
        // a little faded on arrival, more so by the first stop, then steadily clearer
        // through the check, and greener at the end
        const fade = Math.max(0, Math.min(1, phase / 0.33));
        const check = Math.max(0, Math.min(1, (phase - 0.33) / 0.33));
        const heal = Math.max(0, Math.min(1, (phase - 0.33) / 0.67));
        const green = Math.max(0, Math.min(1, (phase - 0.6) / 0.4));
        const gone = (0.3 + 0.3 * fade) * (1 - heal);
        for (i = 0; i < N; i++) {
          f = i / N;
          if (f < 0.88) {
            fromSet(i, pts, 2.1, 0, 0.02, 0.14, 0);
            const r5 = R[i * 6 + 5];
            if (green > 0 && tgt[i * 3 + 1] > 0.75 - green * 1.6) tcol[i] = 1;
            else if (r5 < gone) {
              const drift = (r5 / Math.max(0.001, gone)) * 0.3 + 0.1;
              tgt[i * 3] += (R[i * 6 + 2] - 0.5) * drift * gone;
              tgt[i * 3 + 1] -= (0.3 + R[i * 6 + 4] * 0.6) * drift * gone;
              tgt[i * 3 + 2] += (R[i * 6 + 3] - 0.5) * 0.4 * gone;
              tcol[i] = 4;
            }
          } else if (check > 0) {
            const q = (f - 0.88) / 0.12;
            if (q < 0.4) seg(i, 0.5, 0.06, 0.66, 0.24, 0.07, 1, -0.3);
            else if (check > 0.45) seg(i, 0.66, 0.24, 1.0, -0.2, 0.07, 1, -0.3);
            else sphere(i, 0.66, 0.24, -0.3, 0.05, 1);
          } else sphere(i, 0.75, 0, 0, 1.3, 4);
        }
        break;
      }
      case "sun": {
        // The figures and tier words are drawn flat and the camera holds square, so they
        // stay readable and land in the slot the copy leaves for them.
        spec.yawAmp = 0.05;
        spec.turn = false;
        const y0 = 0.8;
        const sy = 0.6 - phase * 1.0; // already half-risen when the scene opens
        // two stops: Codex alone, then with FinishUP's AI-powered review
        const stop = phase < 0.5 ? 0 : 1;
        // the score counts up from the first figure to the last as the sun crosses the middle;
        // with reduced motion each stop shows its own figure, with none in between. The stops
        // show the supplied figures verbatim; the figures between keep their precision.
        const first = scores[0], last = scores[scores.length - 1];
        const lo = parseFloat(first), hi = parseFloat(last);
        const counts = !reduced && isFinite(lo) && isFinite(hi);
        let shown = scores[Math.min(scores.length - 1, stop)] || "";
        if (counts) {
          const u = Math.round(smooth((phase - 0.42) / 0.16) * COUNT_STEPS) / COUNT_STEPS;
          shown = u <= 0 ? String(first) : u >= 1 ? String(last) : (lo + (hi - lo) * u).toFixed(Math.max(decimalsOf(first), decimalsOf(last)));
        }
        const digits = shown ? wordSet(shown + "%") : null;
        // Beside the sun on wide screens. Its sun-side edge stays put; where the canvas is too
        // narrow for the full-size figure (portrait and square tablets), the figure shrinks
        // toward the sun so its far edge keeps a gutter inside the canvas.
        let digitScale = 0.6, digitX = -0.66;
        if (digits && digits.length && !narrowLayout) {
          const right = -0.66 + 0.6 * digits.hi;
          const left = Math.min(right - 0.2, Math.max(-0.66 + 0.6 * digits.lo, -scoreRoom));
          digitScale = (right - left) / (digits.hi - digits.lo);
          digitX = right - digitScale * digits.hi;
        }
        // the tier word, drawn densely in dots where the copy leaves room for it, its dots
        // sized to the word so it reads at every width
        const tier = stop === 1 && drawTier ? wordSet("AI-powered", true) : null;
        const tsc = tier ? Math.min(tierN.w / tier.width, tierN.h / 0.42) : 0;
        // flush with the copy: right-aligned on wide screens, left-aligned on phones
        const tierX = narrowLayout ? tierN.x - tierN.w / 2 + (tier ? tier.width * tsc : 0) / 2 : tierN.x + tierN.w / 2 - (tier ? tier.width * tsc : 0) / 2;
        const tierDot = Math.max(0.9, Math.min(1.5, (tsc * 0.42 * scaleS) / 55));
        for (i = 0; i < N; i++) {
          f = i / N;
          if (f < 0.18) {
            set(i, (R[i * 6] - 0.5) * 2.3, y0 + (R[i * 6 + 1] - 0.5) * 0.03, (R[i * 6 + 2] - 0.5) * 0.5, 0);
            continue;
          }
          if (f >= 0.45) {
            if (tier) {
              fromSetEven(i, Math.floor(N * 0.45), N, tier, tsc, tierX, tierN.y, 6);
              tbig[i] = tierDot;
            } else sphere(i, 0, sy, 0, 0.17, 2);
            continue;
          }
          if (f >= 0.37 && digits) {
            // the benchmark score, rising with the sun: one figure per stop. Its dots walk the
            // figure evenly, like the tier word's, so it reads within the phone's dot budget.
            const d0 = Math.floor(N * 0.37), d1 = Math.floor(N * 0.45);
            if (narrowLayout) fromSetEven(i, d0, d1, digits, 0.5, 0.02, Math.max(-0.75, Math.min(-0.2, sy - 0.5)), 0);
            else fromSetEven(i, d0, d1, digits, digitScale, digitX, Math.max(-0.2, Math.min(0, sy)), 0);
            tbig[i] = 1.6;
            continue;
          }
          if (f < 0.26) sphere(i, 0, sy, 0, 0.17, 2);
          else {
            a = R[i * 6] * 6.2832;
            const rr = 0.2 + R[i * 6 + 1] * 0.32 * (0.55 + 0.45 * Math.sin(a * 9 + t * 1.5));
            set(i, Math.cos(a) * rr, sy + Math.sin(a) * rr, (R[i * 6 + 2] - 0.5) * 0.1, 3);
          }
          if (tgt[i * 3 + 1] > y0) set(i, (R[i * 6 + 3] - 0.5) * 2.3, y0 + (R[i * 6 + 4] - 0.5) * 0.03, (R[i * 6 + 5] - 0.5) * 0.5, 0);
        }
        break;
      }
      case "hero":
      default: {
        // The word between "We use agents for" and "FinishUP makes sure they do it."
        // It changes on its own until the reader scrolls, then holds.
        if (scroll == null || scroll < HERO_HOLD_AT) heroWord = Math.floor(t / HERO_SECONDS) % HERO_WORDS.length;
        pts = wordSet(HERO_WORDS[heroWord]);
        spec.yawAmp = 0.12;
        for (i = 0; i < N; i++) {
          if (R[i * 6 + 5] < 0.03) sphere(i, 0, -0.16, 0, 1.0, 1);
          else fromSet(i, pts, 0.8, 0, -0.16, 0.14, 0);
        }
      }
    }
    if (spec.turn) {
      // The camera turns with the scroll, about 13 degrees across a scene, alternating
      // direction scene to scene so a scene starts where the last one left the camera.
      spec.orbit = (idx % 2 ? -1 : 1) * (phase - 0.5) * 0.45;
      spec.tilt = -0.16 * Math.sin(Math.PI * phase);
      spec.yawAmp *= 0.35;
    }
    return spec;
  }

  function frame(t) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const cw = canvas.clientWidth;
    const ch = canvas.clientHeight;
    if (!cw || !ch) return;
    if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
      canvas.width = Math.round(cw * dpr);
      canvas.height = Math.round(ch * dpr);
    }
    const S = cw < 720 ? cw * 0.42 : Math.min(cw, ch) * 0.46;
    scaleS = S;
    const nrw = cw < 720;
    narrowLayout = nrw;
    const tl = scroll != null ? timeline(scroll, plan) : null;
    if (reduced) {
      // Pixel anchors must use the camera that this stable frame will draw with.
      ox = SCENE_OFFSETS.get(tl ? tl.a : scene.form) || 0;
      if (tl && tl.b && tl.u > 0) ox += ((SCENE_OFFSETS.get(tl.b) || 0) - ox) * tl.u;
    }
    const cxo = cw / 2 + (nrw ? ox * 0.4 : ox) * cw, cyo = nrw ? ch * 0.36 : ch / 2;
    if (anchor) anchorN = { x: (anchor.x - cxo) / S, y: (anchor.y - cyo) / S };
    if (tierPx) tierN = { x: (tierPx.x - cxo) / S, y: (tierPx.y - cyo) / S, w: tierPx.w / S, h: tierPx.h / S };
    else tierN = defaultTier;
    // the side score's room: from the camera centre to a gutter inside the canvas's left edge,
    // wide enough to absorb the sunrise's slight yaw and perspective
    scoreRoom = (cxo - Math.max(24, cw * 0.04)) / S;
    let spec;
    if (tl) {
      spec = build(tl.a, t, tl.pa, tl.ia);
      if (tl.b && tl.u > 0) {
        tgtA.set(tgt);
        tcolA.set(tcol);
        const specB = build(tl.b, t, tl.pb, tl.ib);
        const u = tl.u;
        // The change sweeps across the form from left to right like a wave, and each dot
        // takes a little turbulence in flight before it settles.
        for (let i = 0; i < N; i++) {
          const j = i * 3;
          const ui = smooth(u * 1.7 - clamp01((tgtA[j] + 1.2) / 2.4) * 0.7);
          const amp = Math.sin(Math.PI * ui) * 0.14;
          tgt[j] = tgtA[j] + (tgt[j] - tgtA[j]) * ui + Math.sin(tgtA[j + 1] * 4 + t * 0.8 + R[i * 6 + 2] * 2) * amp;
          tgt[j + 1] = tgtA[j + 1] + (tgt[j + 1] - tgtA[j + 1]) * ui + Math.cos(tgtA[j] * 4 - t * 0.7 + R[i * 6 + 3] * 2) * amp;
          tgt[j + 2] = tgtA[j + 2] + (tgt[j + 2] - tgtA[j + 2]) * ui + amp * 0.6;
          if (ui < 0.5) tcol[i] = tcolA[i];
        }
        spec = {
          tilt: spec.tilt + (specB.tilt - spec.tilt) * u,
          ox: spec.ox + (specB.ox - spec.ox) * u,
          yawAmp: spec.yawAmp + (specB.yawAmp - spec.yawAmp) * u,
          orbit: spec.orbit + (specB.orbit - spec.orbit) * u,
          mouse: u < 0.5 ? spec.mouse : specB.mouse,
          still: u < 0.5 ? spec.still : specB.still,
        };
      }
    } else {
      spec = build(scene.form, t, clamp01(scene.phase || 0), 0);
    }
    if (reduced) {
      // One stable rendering per state change, with no spring or camera settling.
      pos.set(tgt);
      vel.fill(0);
      col.set(tcol);
      big.set(tbig);
      tilt = 0;
      ox = spec.ox;
      orb = jit = smx = 0;
    } else {
      // Each dot is a damped spring on its target: it arrives with a little inertia.
      for (let i = 0; i < N; i++) {
        const ks = 0.006 + R[i * 6 + 4] * 0.006;
        const j = i * 3;
        const dx = tgt[j] - pos[j];
        const dy = tgt[j + 1] - pos[j + 1];
        const dz = tgt[j + 2] - pos[j + 2];
        vel[j] = (vel[j] + dx * ks) * 0.88;
        vel[j + 1] = (vel[j + 1] + dy * ks) * 0.88;
        vel[j + 2] = (vel[j + 2] + dz * ks) * 0.88;
        pos[j] += vel[j];
        pos[j + 1] += vel[j + 1];
        pos[j + 2] += vel[j + 2];
        if (dx * dx + dy * dy + dz * dz < 0.02) col[i] = tcol[i];
        big[i] += (tbig[i] - big[i]) * 0.08;
      }
      tilt += (spec.tilt - tilt) * 0.04;
      ox += (spec.ox - ox) * 0.04;
      orb += (spec.orbit - orb) * 0.06;
      jit += ((spec.still ? 0 : 0.5) - jit) * 0.05;
      smx += ((spec.mouse ? mx : 0) - smx) * 0.05;
    }
    const yaw = reduced ? 0 : Math.sin(t * 0.12) * spec.yawAmp + orb + smx * 0.3;
    const cy0 = Math.cos(yaw), sy0 = Math.sin(yaw), ct = Math.cos(tilt), st = Math.sin(tilt);
    const narrow = cw < 720;
    const cx = cw / 2 + (narrow ? ox * 0.4 : ox) * cw;
    const cy = narrow ? ch * 0.36 : ch / 2;
    const F = 2.6;
    for (let i = 0; i < N; i++) {
      const j = i * 3;
      const x = pos[j], y = pos[j + 1], z = pos[j + 2];
      const x1 = x * cy0 - z * sy0;
      const z1 = x * sy0 + z * cy0;
      const y2 = y * ct - z1 * st;
      const z2 = y * st + z1 * ct;
      const sc = F / (F + z2);
      const jj = col[i] >= 5 ? 0 : jit;
      px[i] = cx + x1 * S * sc + Math.sin(t * 2.2 + i) * jj;
      py[i] = cy + y2 * S * sc + Math.cos(t * 1.9 + i * 0.7) * jj;
      ps[i] = (0.8 + R[i * 6 + 1] * 1.4) * 1.3 * sc * big[i] * (col[i] >= 5 ? 1.25 : 1);
      const dep = 1 - (Math.max(-1.2, Math.min(1.2, z2)) + 1.2) / 2.4;
      pa[i] = col[i] >= 5 ? 1 : 0.22 + dep * 0.78;
    }
    const PAL = [PALETTE.particle, PALETTE.signal, sun, sun, PALETTE.faint, PALETTE.silver, PALETTE.gold];
    const AM = [1, 1, 1, 0.5, 0.8, 1, 1];
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cw, ch);
    // the haze first, behind everything
    ctx.fillStyle = PALETTE.particle;
    for (let i = 0; i < BG; i++) {
      const ph = bg[i * 4 + 3];
      const x = bg[i * 4] + Math.sin(t * 0.13 + ph) * 0.06;
      const y = bg[i * 4 + 1] + Math.cos(t * 0.11 + ph * 1.3) * 0.06;
      const z = bg[i * 4 + 2];
      const x1 = x * cy0 - z * sy0;
      const z1 = x * sy0 + z * cy0;
      const y2 = y * ct - z1 * st;
      const z2 = y * st + z1 * ct;
      const sc = F / (F + z2);
      const dep = 1 - Math.max(0, Math.min(1, (z2 - 0.2) / 1.6));
      ctx.globalAlpha = 0.05 + dep * 0.16;
      const s = (0.8 + (ph / 6.2832) * 1.2) * sc * 0.7;
      ctx.fillRect(cx + x1 * S * sc, cy + y2 * S * sc, s, s);
    }
    for (let c = 0; c < PAL.length; c++) {
      const dot = sprite(PAL[c]);
      const am = AM[c];
      for (let i = 0; i < N; i++) {
        if (col[i] !== c) continue;
        ctx.globalAlpha = pa[i] * am;
        const s = ps[i];
        ctx.drawImage(dot, px[i] - s / 2, py[i] - s / 2, s, s);
      }
    }
    ctx.globalAlpha = 1;
  }

  const canRender = () => !destroyed && visible && !document.hidden;
  function schedule() {
    if (!raf && canRender() && (!reduced || dirty)) raf = requestAnimationFrame(loop);
  }
  function invalidate() {
    if (destroyed) return;
    dirty = true;
    schedule();
  }
  function syncActivity() {
    if (destroyed) return;
    if (canRender()) invalidate();
    else {
      cancelAnimationFrame(raf);
      raf = 0;
      lastTime = null;
    }
  }
  function loop(now) {
    raf = 0;
    if (!canRender()) return;
    if (!reduced) {
      if (lastTime !== null) elapsed += Math.max(0, (now - lastTime) / 1000);
      lastTime = now;
    }
    if (!reduced || dirty) {
      dirty = false;
      frame(reduced ? 0 : elapsed);
    }
    schedule();
  }
  const onMove = (e) => {
    mx = e.clientX / Math.max(1, window.innerWidth) - 0.5;
  };
  if (!reduced) window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("resize", invalidate);
  document.addEventListener("visibilitychange", syncActivity);
  let io = null;
  if (typeof IntersectionObserver !== "undefined") {
    io = new IntersectionObserver((en) => {
      if (destroyed) return;
      visible = !!(en[0] && en[0].isIntersecting);
      syncActivity();
    });
    io.observe(canvas);
  }
  if (document.fonts && document.fonts.load) {
    document.fonts
      .load('600 120px "Geist"')
      .then(() => {
        if (destroyed) return;
        cache = {};
        invalidate();
      })
      .catch(() => {});
  }
  schedule();

  return {
    setScene(form, phase) {
      if (scroll === null && scene.form === form && scene.phase === phase) return;
      scroll = null;
      scene = { form, phase };
      invalidate();
    },
    // screens scrolled into the story; the engine picks and blends the scenes itself
    setScroll(screens) {
      if (scroll === screens) return;
      scroll = screens;
      invalidate();
    },
    // x, y in canvas pixels; null to fall back to the default spot.
    setAnchor(x, y) {
      if (x == null ? anchor === null : anchor && anchor.x === x && anchor.y === y) return;
      anchor = x == null ? null : { x, y };
      invalidate();
    },
    // the slot (canvas pixels: centre and size) where "AI-powered" is drawn in dots
    setTier(x, y, w, h) {
      if (x == null ? tierPx === null : tierPx && tierPx.x === x && tierPx.y === y && tierPx.w === w && tierPx.h === h) return;
      tierPx = x == null ? null : { x, y, w, h };
      invalidate();
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      cancelAnimationFrame(raf);
      raf = 0;
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("resize", invalidate);
      document.removeEventListener("visibilitychange", syncActivity);
      if (io) io.disconnect();
    },
  };
}
