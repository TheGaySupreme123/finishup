// FinishUP particle artwork: points that rearrange, like atoms, into each scene of the story
// (the words agents do, a clock, a swarm of agents, a robot that fades and is checked back to
// green, a sun that rises with the score, the lockup). The page tells the engine which scene
// is in view and how far through it the reader is; the engine does the rest with a light 3D
// projection. On a 2D canvas it draws a few thousand points. With WebGL2 it draws tens of
// thousands, scaled to the screen: the scenes stand on a sea of dots, and each scene change
// is a storm that sweeps the whole screen (see stormBlend).

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
// `blend` is the half-width of each change; it never takes more than 0.45 of either scene.
function timeline(s, plan, blend = BLEND) {
  const half = (k) => Math.min(blend, plan[k][1] * 0.45, plan[k + 1][1] * 0.45);
  let acc = 0;
  for (let i = 0; i < plan.length; i++) {
    const [name, len] = plan[i];
    const end = acc + len;
    if (s < end || i === plan.length - 1) {
      const pa = clamp01((s - acc) / len);
      const bEnd = i < plan.length - 1 ? half(i) : 0;
      const bStart = i > 0 ? half(i - 1) : 0;
      if (i < plan.length - 1 && s > end - bEnd) {
        return { a: name, ia: i, pa, b: plan[i + 1][0], ib: i + 1, pb: clamp01((s - end) / plan[i + 1][1]), u: smooth((s - (end - bEnd)) / (2 * bEnd)) };
      }
      if (i > 0 && s < acc + bStart) {
        return { a: plan[i - 1][0], ia: i - 1, pa: 1, b: name, ib: i, pb: pa, u: smooth((s - (acc - bStart)) / (2 * bStart)) };
      }
      return { a: name, ia: i, pa, b: null, ib: -1, pb: 0, u: 0 };
    }
    acc = end;
  }
  return { a: "end", ia: plan.length - 1, pa: 1, b: null, ib: -1, pb: 0, u: 0 };
}

// The WebGL2 path draws every dot as a soft round point in its palette colour, in one call, so
// the artwork can carry ten times as many dots as the 2D path. Each point is x, y (CSS px),
// size (CSS px), alpha and a palette index.
const GL_STRIDE = 5;
const GL_VERT = `#version 300 es
layout(location = 0) in vec2 a_pos;
layout(location = 1) in vec3 a_sac;
uniform vec2 u_view;
uniform float u_dpr;
uniform vec3 u_pal[8];
out vec4 v_col;
void main() {
  vec2 c = a_pos / u_view * 2.0 - 1.0;
  gl_Position = vec4(c.x, -c.y, 0.0, 1.0);
  float s = a_sac.x * u_dpr;
  gl_PointSize = max(1.0, s);
  // a dot smaller than a device pixel covers only part of it
  float a = a_sac.y * min(1.0, max(0.55, s));
  v_col = vec4(u_pal[int(a_sac.z + 0.5)] * a, a);
}`;
const GL_FRAG = `#version 300 es
precision mediump float;
in vec4 v_col;
out vec4 o;
void main() {
  vec2 d = gl_PointCoord - 0.5;
  float r = dot(d, d) * 4.0;
  if (r > 1.0) discard;
  o = v_col * (1.0 - smoothstep(0.55, 1.0, r));
}`;
// A swirling, divergence-free flow (an ABC flow drifting in time): neighbouring dots move
// together in streams and eddies, rather than each buzzing on its own.
function flow(x, y, z, t, out) {
  out[0] = Math.sin(z + t * 0.21) + Math.cos(y + t * 0.17);
  out[1] = Math.sin(x + t * 0.19) + Math.cos(z + t * 0.23);
  out[2] = Math.sin(y + t * 0.15) + Math.cos(x + t * 0.2);
}
const rgb = (hex) => [1, 3, 5].map((k) => parseInt(hex.slice(k, k + 2), 16) / 255);

// `hooks.lost` / `hooks.restored` hear about context loss. Software-rendered WebGL is refused
// (failIfMajorPerformanceCaveat), so slow machines keep the lighter 2D artwork.
function glRenderer(canvas, palette, hooks = {}) {
  const gl = canvas.getContext("webgl2", { alpha: true, premultipliedAlpha: true, antialias: false, depth: false, stencil: false, failIfMajorPerformanceCaveat: true });
  if (!gl || typeof gl.createShader !== "function" || gl.isContextLost()) return null;
  const pal = new Float32Array(24);
  palette.forEach((hex, k) => pal.set(rgb(hex), k * 3));
  let prog = null, vao = null, vbo = null, loc = null, cap = 0, lost = false;
  const init = () => {
    const shader = (type, src) => {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return s;
    };
    const vs = shader(gl.VERTEX_SHADER, GL_VERT);
    const fs = shader(gl.FRAGMENT_SHADER, GL_FRAG);
    prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.deleteShader(vs);
    gl.deleteShader(fs);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    vbo = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, GL_STRIDE * 4, 0);
    gl.enableVertexAttribArray(1);
    gl.vertexAttribPointer(1, 3, gl.FLOAT, false, GL_STRIDE * 4, 8);
    loc = { view: gl.getUniformLocation(prog, "u_view"), dpr: gl.getUniformLocation(prog, "u_dpr"), pal: gl.getUniformLocation(prog, "u_pal") };
    cap = 0;
    return true;
  };
  const tryInit = () => {
    try {
      return init();
    } catch {
      return false;
    }
  };
  if (!tryInit()) return null;
  const onLost = (e) => { e.preventDefault(); lost = true; hooks.lost?.(); };
  const onRestored = () => { lost = !tryInit(); if (!lost) hooks.restored?.(); };
  canvas.addEventListener("webglcontextlost", onLost);
  canvas.addEventListener("webglcontextrestored", onRestored);
  return {
    get lost() { return lost; },
    draw(cw, ch, dpr, data, count) {
      if (lost || gl.isContextLost()) return;
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(prog);
      gl.bindVertexArray(vao);
      gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
      if (count * GL_STRIDE > cap) {
        cap = data.length;
        gl.bufferData(gl.ARRAY_BUFFER, data.byteLength, gl.DYNAMIC_DRAW);
      }
      gl.bufferSubData(gl.ARRAY_BUFFER, 0, data, 0, count * GL_STRIDE);
      gl.uniform2f(loc.view, cw, ch);
      gl.uniform1f(loc.dpr, dpr);
      gl.uniform3fv(loc.pal, pal);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
      gl.drawArrays(gl.POINTS, 0, count);
    },
    dispose() {
      canvas.removeEventListener("webglcontextlost", onLost);
      canvas.removeEventListener("webglcontextrestored", onRestored);
      if (gl.isContextLost()) return;
      gl.deleteBuffer(vbo);
      gl.deleteVertexArray(vao);
      gl.deleteProgram(prog);
    },
  };
}

// Whether this browser can run the WebGL path, asked once on a throwaway canvas: a canvas that
// has handed out a WebGL context can never fall back to 2D.
let glSupported = null;
function canUseGL() {
  if (glSupported !== null) return glSupported;
  glSupported = false;
  try {
    const probe = document.createElement("canvas");
    const r = glRenderer(probe, ["#000000"]);
    if (r) {
      glSupported = true;
      r.dispose();
      const gl = probe.getContext("webgl2");
      gl?.getExtension("WEBGL_lose_context")?.loseContext();
    }
  } catch {
    glSupported = false;
  }
  return glSupported;
}

export function mountParticles(canvas, options = {}) {
  const sun = options.sun || "#E9B200";
  const PAL = [PALETTE.particle, PALETTE.signal, sun, sun, PALETTE.faint, PALETTE.silver, PALETTE.gold];
  const AM = [1, 1, 1, 0.5, 0.8, 1, 1];
  // With a WebGL budget and a browser that can draw it, the dots go to the GPU; otherwise the
  // 2D budget applies.
  // A lost context that is not restored within a few seconds is reported through
  // options.onUnavailable, so the page can show its static story instead of a blank canvas.
  let lostTimer = 0;
  const glHooks = {
    lost() {
      clearTimeout(lostTimer);
      lostTimer = setTimeout(() => options.onUnavailable?.(), 3000);
    },
    restored() {
      clearTimeout(lostTimer);
      invalidate();
    },
  };
  const gl = options.glCount && canUseGL() ? glRenderer(canvas, [ "#042F24", "#059669", sun, sun, PALETTE.faint, PALETTE.silver, PALETTE.gold ], glHooks) : null;
  const ctx = gl ? null : canvas.getContext("2d");
  if (gl) AM[3] = 0.78; // the sun's corona carries further in the denser artwork
  // `renderer` tells the page what it got: "webgl", "2d", or "none" (draw nothing; show the
  // static story).
  if (!gl && !ctx) return { renderer: "none", setScene() {}, setScroll() {}, setAnchor() {}, setTier() {}, setLockup() {}, destroy() {} };
  const reduced = !!options.reducedMotion;
  const N = gl ? Math.max(800, Math.min(200000, options.glCount)) : Math.max(800, Math.min(9000, options.count || 9000));
  // Denser artwork draws finer dots, so the shapes gain grain rather than weight.
  // With WebGL a dot's size follows the scene's scale (px per scene unit) and the dot count, so
  // the same share of each shape is ink on a phone as on a desktop; 368 px per unit with 60k
  // dots is the reference.
  const dotRef = gl ? 0.68 * Math.sqrt(60000 / N) : 1;
  // Scores are evidence supplied by the caller, never an artwork default.
  const scores = options.scores || [];
  const drawTier = options.drawTier !== false;
  const plan = options.plan && options.plan.length ? options.plan : PLAN;

  const pos = new Float32Array(N * 3);
  const vel = new Float32Array(N * 3);
  const tgt = new Float32Array(N * 3);
  const tgtA = new Float32Array(N * 3);
  const tcolA = new Uint8Array(N);
  const tbigA = new Float32Array(N); // the old scene's dot sizes and roles, during a change
  const roleA = new Uint8Array(N);
  const col = new Uint8Array(N);
  const tcol = new Uint8Array(N);
  const px = new Float32Array(N);
  const py = new Float32Array(N);
  const ps = new Float32Array(N);
  const big = new Float32Array(N); // dot size multiplier: the benchmark's figures and words keep larger dots
  const tbig = new Float32Array(N);
  // what a dot is in this frame's scene: 0 part of a shape, 1 a word or figure that must read,
  // 2 the sea. Breathing, the halo and the springs treat them differently.
  const role = new Uint8Array(N);
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
  // gather from and dissolve back into. The WebGL artwork has none: every one of its dots
  // belongs to the scene (a shape, the sea under it, or the storm between scenes).
  const rich = !!gl;
  const BG = rich ? 0 : Math.round(N * 0.5);
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
  // On the dense WebGL path many dots share one sample, so each takes a place of its own
  // within that sample's cell (its own stream, so the 2D artwork is unchanged).
  const J = new Float32Array(gl ? N * 2 : 0);
  let jseed = 17;
  for (let i = 0; i < J.length; i++) {
    jseed = (Math.imul(jseed, 1664525) + 1013904223) >>> 0;
    J[i] = jseed / 4294967296 - 0.5;
  }
  // Each dot's own draws for the weather: its place in the storm and in the band, when it
  // leaves, and whether it is one of the loose ones that wander off a shape.
  const Q = new Float32Array(rich ? N * 5 : 0);
  let qseed = 29;
  for (let i = 0; i < Q.length; i++) {
    qseed = (Math.imul(qseed, 1664525) + 1013904223) >>> 0;
    Q[i] = qseed / 4294967296;
  }
  // powers of those draws that every frame would otherwise recompute
  const QP = new Float32Array(rich ? N * 3 : 0);
  for (let i = 0; i < QP.length / 3; i++) {
    QP[i * 3] = Math.pow(Q[i * 5 + 1], 1.35);
    QP[i * 3 + 1] = Math.pow(Q[i * 5 + 2], 0.78);
    QP[i * 3 + 2] = Math.pow(Q[i * 5 + 4], 2.2);
  }
  const fl = [0, 0, 0];
  // On the dense path each frame recomputes the targets of half the dots, alternating; the
  // springs carry them smoothly in between. I0 is this frame's half, IS the stride.
  let I0 = 0, IS = 1, frames = 0;
  // With WebGL a little over a fifth of the dots are the sea under every scene; the scenes
  // share the rest.
  const NS = rich ? Math.floor(N * 0.78) : N;
  let viewL = -1.6, viewR = 1.6;
  let gust = 0; // how hard the storm blows: 0 at rest, 1 in the middle of a scene change
  const glData = gl ? new Float32Array(N * GL_STRIDE) : null;
  const colStart = new Int32Array(8);

  let cache = {};
  const off = document.createElement("canvas");
  off.width = 900;
  off.height = 300;
  const offCtx = off.getContext("2d", { willReadFrequently: true });
  // one sampling cell (see sample) in scene units
  const cell = gl ? 4 / off.width : 0;
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
  let lockPx = null; // the slot above the closing line where the lockup is drawn
  let lockN = null;
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
    role[i] = 0;
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
      if (rich) {
        const zh = Math.min(0.32, Math.sqrt(pts.dep[idx]) * 0.55 + 0.02) * Math.min(sc, 1.6);
        z = R[i * 6 + 4] < 0.65 ? (R[i * 6 + 4] / 0.65 * 2 - 1) * zh : (R[i * 6 + 4] < 0.825 ? -1 : 1) * zh;
      } else {
        const zh = Math.min(0.08, pts.dep[idx] * 0.8 + 0.01);
        z = (R[i * 6 + 4] < 0.5 ? -1 : 1) * zh * Math.min(sc, 1.2) * (0.8 + R[i * 6 + 2] * 0.2);
      }
    }
    const jx = cell ? J[i * 2] * cell : 0, jy = cell ? J[i * 2 + 1] * cell : 0;
    set(i, (pts[j] + jx) * sc + dx, (pts[j + 1] + jy) * sc + dy, z, c == null ? (pts[j + 2] ? 1 : 0) : c);
    // relief: heavier dots in the body's core and on its shadow (left) side
    if (rich && !flat) tbig[i] = 1.05 + 0.45 * clamp01(pts.dep[idx] * 3.5) + (pts[j] < 0 ? 0.2 : -0.1);
  };
  // like fromSet, but points i0..i1 walk the sample in order, so coverage is even and
  // the letters read crisply (no clumps, no gaps, no depth jitter)
  const fromSetEven = (i, i0, i1, pts, sc, dx, dy, c) => {
    const n = pts.length / 3;
    if (!n) return scatter(i);
    const j = Math.min(n - 1, Math.floor(((i - i0) / Math.max(1, i1 - i0)) * n)) * 3;
    const jx = cell ? J[i * 2] * cell : 0, jy = cell ? J[i * 2 + 1] * cell : 0;
    set(i, (pts[j] + jx) * sc + dx, (pts[j + 1] + jy) * sc + dy, 0, c);
    role[i] = 1;
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
    let lo = 9, hi = -9, top = 9, bottom = -9, mx0 = 0, my0 = 0;
    for (let j = 0; j < n; j++) {
      const x = pts[j * 3], y = pts[j * 3 + 1];
      if (x < lo) lo = x;
      if (x > hi) hi = x;
      if (y < top) top = y;
      if (y > bottom) bottom = y;
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
    pts.top = top;
    pts.bottom = bottom;
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
      // Proportions from the lockup artwork: the box is open at its top right (the top bar
      // stops a third of the way across, the right bar starts about halfway down) and the
      // check sits in that opening, clear of both bars.
      const x = 50, y = 95, w = 140, h = 140, r = 26;
      c.lineCap = "round";
      c.lineJoin = "round";
      c.strokeStyle = "#000";
      c.lineWidth = 37;
      c.beginPath();
      c.moveTo(x + w, y + 79);
      c.arcTo(x + w, y + h, x, y + h, r);
      c.arcTo(x, y + h, x, y, r);
      c.arcTo(x, y, x + w, y, r);
      c.lineTo(x + 52, y);
      c.stroke();
      c.strokeStyle = "#00ff00";
      c.lineWidth = 27;
      c.beginPath();
      c.moveTo(x + 101, y - 1);
      c.lineTo(x + 124, y + 26);
      c.lineTo(x + 184, y - 34);
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

  // A dot of the sea at depth z (near the camera to the far distance), spread wider with
  // distance so the plane reaches both edges of the screen, on slow rolling swells.
  const SEA_Y = 0.72, SEA_NEAR = -0.45;
  let seaNow = 1.6;
  // `seaDrop` lowers the whole sea (scene units); the closing scene sinks it off a phone screen.
  let seaDrop = 0;
  function seaDot(i, t, far) {
    const q = i * 5;
    const z = SEA_NEAR + QP[i * 3] * (far - SEA_NEAR);
    const hw = Math.max(-viewL, viewR, 1) * ((2.6 + z) / 2.6) * 1.2 + Math.abs(z) * 0.3 + 0.3;
    const x = (Q[q + 2] * 2 - 1) * hw;
    const y = SEA_Y + seaDrop + 0.05 * Math.sin(x * 1.4 + t * 0.7) + 0.06 * Math.sin(z * 0.9 - t * 0.55) + 0.025 * Math.sin((x - z) * 2.7 + t * 1.1);
    set(i, x, y, z, 0);
    tbig[i] = 0.85;
    role[i] = 2;
  }

  // `idx` is the scene's place in the plan; `phase` how far through it the reader is.
  function build(name, t, phase, idx, seaSame = null) {
    // orbit: how far the camera has turned with the scroll; still: the scene holds
    // perfectly still once formed (the closing lockup)
    const spec = { tilt: 0, ox: SCENE_OFFSETS.get(name) || 0, yawAmp: 0.26, orbit: 0, mouse: true, still: false, turn: true, seaFar: 1.6, seaDrop: 0, halo: 0.055, focus: 0 };
    // the sea starts from this scene's own settings, never the last build's
    seaNow = spec.seaFar;
    seaDrop = 0;
    let pts, i, f, k, a;
    switch (name) {
      case "logo":
      case "end": {
        // The lockup, in the slot the closing copy leaves above "is free." (or the top third
        // without one), and then frozen: it stays exactly as drawn while the page scrolls on.
        pts = logoSet();
        spec.yawAmp = 0;
        spec.mouse = false;
        spec.still = true;
        spec.turn = false;
        spec.seaFar = -0.2;
        // on a phone the closing copy fills the middle of the screen, so the sea sinks away
        if (narrowLayout) spec.seaDrop = 3;
        spec.halo = 0;
        // When the page gives it a slot (above "is free."), the lockup fills it, centred.
        let lsc = 0.56, lx = 0, ly = narrowLayout ? -0.62 : -0.7, halo = 0.8;
        if (lockN && pts.length) {
          lsc = Math.min(lockN.w / Math.max(0.01, pts.hi - pts.lo), lockN.h / Math.max(0.01, pts.bottom - pts.top));
          lx = lockN.x - ((pts.lo + pts.hi) / 2) * lsc;
          ly = lockN.y - ((pts.top + pts.bottom) / 2) * lsc;
          halo = lockN.w * 0.7;
        }
        for (i = I0; i < NS; i += IS) {
          f = i / NS;
          if (f < 0.96) fromSet(i, pts, lsc, lx, ly, 0.04, null, true);
          else sphere(i, lockN ? lockN.x : 0, lockN ? lockN.y : ly, 0, halo, 1);
        }
        break;
      }
      case "alone": {
        // the clock's hands follow the scroll: an hour and a half passes in this scene
        pts = figureSet();
        const hA = -1.5708 + phase * 0.9;
        const mA = -1.5708 + phase * 9.4248;
        for (i = I0; i < NS; i += IS) {
          f = i / NS;
          if (rich) {
            spec.focus = -0.45;
            if (f < 0.34) fromSet(i, pts, 1.9, -0.74, 0.26, 0.12, 0);
            else clock(i, (f - 0.34) / 0.66, -0.16, -0.1, 0.42, hA, mA);
          } else if (f < 0.3) fromSet(i, pts, 1.1, -0.58, 0.04, 0.12, 0);
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
        for (i = I0; i < NS; i += IS) {
          f = i / NS;
          if (rich) {
            // a deep orbit: robots in front pass near the camera, those behind go misty
            spec.focus = -0.48;
            if (f < 0.3) fromSet(i, pts, 1.65, -0.48, 0.26, 0.12, 0);
            else if (f < 0.42) clock(i, (f - 0.3) / 0.12, -0.48, -0.58, 0.22, hA, mA);
            else {
              k = Math.floor(((f - 0.42) / 0.58) * 6);
              a = (k / 6) * 6.2832 + t * 0.35;
              fromSet(i, bots, 0.62, -0.48 + Math.cos(a) * 0.62, 0.05 + Math.sin(a) * 0.22, 0.1, R[i * 6 + 5] < 0.06 ? 1 : 0);
              tgt[i * 3 + 2] += Math.sin(a) * 0.65;
            }
          } else if (f < 0.3) fromSet(i, pts, 1.05, 0, 0.02, 0.12, 0);
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
        if (rich) spec.focus = -0.2; // the robot and its check, together
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
        const gone = (rich ? 0.1 + 0.22 * fade : 0.3 + 0.3 * fade) * (1 - heal);
        for (i = I0; i < NS; i += IS) {
          f = i / NS;
          if (f < 0.88) {
            if (rich) fromSet(i, pts, 2.5, -0.46, 0.24, 0.14, 0);
            else fromSet(i, pts, 2.1, 0, 0.02, 0.14, 0);
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
            const ck = rich ? -0.42 : 0; // the dense path's robot stands further left
            if (q < 0.4) seg(i, 0.5 + ck, 0.06, 0.66 + ck, 0.24, 0.07, 1, -0.3);
            else if (check > 0.45) seg(i, 0.66 + ck, 0.24, 1.0 + ck, -0.2, 0.07, 1, -0.3);
            else sphere(i, 0.66 + ck, 0.24, -0.3, 0.05, 1);
          } else if (rich) fromSet(i, pts, 2.5, -0.46, 0.24, 0.14, 0);
          else sphere(i, 0.75, 0, 0, 1.3, 4);
        }
        break;
      }
      case "sun": {
        // The figures and tier words are drawn flat and the camera holds square, with no
        // sway and no pointer parallax (as for the closing lockup), so they stay readable and
        // land in the slot the copy leaves for them.
        spec.yawAmp = 0;
        spec.mouse = false;
        spec.turn = false;
        // With the sea, the horizon is the sea's own and the sun climbs out of it.
        const y0 = rich ? 0.38 : 0.8;
        const sy = rich ? 0.4 - phase * 0.9 : 0.6 - phase * 1.0; // already half-risen when the scene opens
        const sr = rich ? 0.3 : 0.17, rk = rich ? 1.25 : 1, sx = rich ? -0.28 : 0;
        spec.focus = sx;
        if (rich) spec.halo = 0.02;
        // two stops: Codex as it was tested on the suite, then tested with FinishUP
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
        const dAnchor = rich ? -0.94 : -0.66;
        let digitScale = 0.6, digitX = dAnchor;
        if (digits && digits.length && !narrowLayout) {
          const right = dAnchor + 0.6 * digits.hi;
          const left = Math.min(right - 0.2, Math.max(dAnchor + 0.6 * digits.lo, -scoreRoom));
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
        for (i = I0; i < NS; i += IS) {
          f = i / NS;
          if (f < 0.18) {
            if (rich) seaDot(i, t, seaNow);
            else set(i, (R[i * 6] - 0.5) * 2.3, y0 + (R[i * 6 + 1] - 0.5) * 0.03, (R[i * 6 + 2] - 0.5) * 0.5, 0);
            continue;
          }
          if (f >= 0.45) {
            if (tier) {
              fromSetEven(i, Math.floor(NS * 0.45), NS, tier, tsc, tierX, tierN.y, 6);
              tbig[i] = tierDot;
            } else sphere(i, sx, sy, 0, sr, 2);
            continue;
          }
          if (f >= 0.37 && digits) {
            // the benchmark score, rising with the sun: one figure per stop. Its dots walk the
            // figure evenly, like the tier word's, so it reads within the phone's dot budget.
            const d0 = Math.floor(NS * 0.37), d1 = Math.floor(NS * 0.45);
            if (narrowLayout) fromSetEven(i, d0, d1, digits, 0.5, sx + 0.02, Math.max(-0.75, Math.min(-0.2, sy - 0.5)), 0);
            else fromSetEven(i, d0, d1, digits, digitScale, digitX, Math.max(-0.2, Math.min(0, sy)), 0);
            tbig[i] = 1.6;
            continue;
          }
          if (f < 0.26) sphere(i, sx, sy, 0, sr, 2);
          else {
            a = R[i * 6] * 6.2832;
            const rr = (0.2 + R[i * 6 + 1] * 0.32 * (0.55 + 0.45 * Math.sin(a * 9 + t * 1.5))) * rk;
            set(i, sx + Math.cos(a) * rr, sy + Math.sin(a) * rr, (R[i * 6 + 2] - 0.5) * 0.1, 3);
          }
          if (tgt[i * 3 + 1] > y0) {
            if (rich) seaDot(i, t, seaNow);
            else set(i, (R[i * 6 + 3] - 0.5) * 2.3, y0 + (R[i * 6 + 4] - 0.5) * 0.03, (R[i * 6 + 5] - 0.5) * 0.5, 0);
          }
        }
        break;
      }
      case "hero":
      default: {
        // The word between "We use agents for" and "FinishUP makes sure they do it."
        // It changes on its own until the reader scrolls, then holds.
        if (scroll == null || scroll < (rich ? 0.44 : HERO_HOLD_AT)) heroWord = Math.floor(t / HERO_SECONDS) % HERO_WORDS.length;
        pts = wordSet(HERO_WORDS[heroWord]);
        spec.yawAmp = 0.12;
        spec.halo = 0.03; // the word must still read
        for (i = I0; i < NS; i += IS) {
          if (R[i * 6 + 5] < 0.03) sphere(i, 0, -0.16, 0, 1.0, 1);
          else fromSet(i, pts, narrowLayout ? 0.9 : 1.05, 0, -0.16, 0.14, 0);
        }
      }
    }
    // The sea: the rest of the dots lie in a rolling plane of dots under every scene, from
    // the bottom of the screen toward the horizon, fading with distance.
    if (rich) {
      seaNow = spec.seaFar;
      seaDrop = spec.seaDrop;
      if (seaSame !== spec.seaFar + spec.seaDrop * 1000) for (i = NS + ((((I0 - NS) % IS) + IS) % IS); i < N; i += IS) seaDot(i, t, seaNow);
      // The halo: some of each shape's dots shed off it, mostly close in and drifting
      // outward and up, a few further out into the air around it (words and figures that must
      // read keep all their dots).
      if (spec.halo > 0) {
        let hx = 0, hy = 0, hn = 0;
        for (i = I0; i < NS; i += IS) {
          if (role[i] !== 0) continue;
          hx += tgt[i * 3];
          hy += tgt[i * 3 + 1];
          hn++;
        }
        hx /= Math.max(1, hn);
        hy /= Math.max(1, hn);
        const near = spec.halo * 0.75, far = spec.halo, nearP = Math.pow(near, 2.2);
        for (i = I0; i < NS; i += IS) {
          const q = Q[i * 5 + 4];
          if (q >= far || role[i] !== 0) continue;
          const j = i * 3;
          let dx = tgt[j] - hx, dy = tgt[j + 1] - hy;
          const d = Math.sqrt(dx * dx + dy * dy) || 1;
          // mostly downwind and up, a little away from the body
          dx = 0.65 * (i % 2 ? -1 : 1) + 0.35 * dx / d;
          dy = -0.45 + 0.25 * dy / d;
          const r = q < near ? 0.015 + 0.07 * (QP[i * 3 + 2] / nearP) : 0.085 + 0.14 * ((q - near) / (far - near));
          tgt[j] += dx * r + (Q[i * 5] - 0.5) * r * 0.6;
          tgt[j + 1] += dy * r + (Q[i * 5 + 3] - 0.5) * r * 0.6;
          tgt[j + 2] += (Q[i * 5 + 2] - 0.5) * r;
        }
      }
    }
    // On a phone the copy sits below the artwork, so the camera centres on the subjects
    // (ox is a fraction of the canvas width, scaled by 0.4 on narrow screens; S is 0.42 of it).
    if (rich && narrowLayout && spec.focus) spec.ox = -spec.focus * 1.05;
    if (spec.turn) {
      // The camera turns with the scroll, about 13 degrees across a scene, alternating
      // direction scene to scene so a scene starts where the last one left the camera.
      spec.orbit = (idx % 2 ? -1 : 1) * (phase - 0.5) * (rich ? 0.72 : 0.45);
      spec.tilt = (rich ? -0.12 : -0.16) * Math.sin(Math.PI * phase);
      spec.yawAmp *= 0.35;
    }
    return spec;
  }

  // A scene change as weather (after the transitions in the reference): the old shape erodes
  // from the top and slumps toward the ground, shearing along the wind; it bursts into a
  // blizzard over the whole screen that drifts with the wind; gathers into a long tilted
  // ribbon; and condenses into the next shape, with a fifth of the dots trailing in late.
  // It runs on the scroll, so it plays backwards too. `dir` is the wind: +1 blows right.
  function stormBlend(u, t, xl, xr, yt, yb, dir) {
    // the old scene's middle, and the arriving shape's middle from its own dots (not the sea),
    // over the dots rebuilt this frame (the other half still hold last frame's storm)
    let ax = 0, ay = 0, an = 0, bx = 0, by = 0, bn = 0;
    for (let i = I0; i < N; i += IS) {
      ax += tgtA[i * 3];
      ay += tgtA[i * 3 + 1];
      an++;
      if (i < NS) {
        bx += tgt[i * 3];
        by += tgt[i * 3 + 1];
        bn++;
      }
    }
    ax /= Math.max(1, an); ay /= Math.max(1, an);
    bx /= Math.max(1, bn); by /= Math.max(1, bn);
    const W = xr - xl, H = yb - yt;
    const midY = (yt + yb) / 2 - 0.05 * H;
    // the storm comes into the new shape from a canopy above, or surges up from below
    const entry = (dir > 0 ? -0.25 : 0.22) * H;
    for (let i = I0; i < N; i += IS) {
      const j = i * 3, q = i * 5;
      const q0 = Q[q];
      const Ax = tgtA[j], Ay = tgtA[j + 1], Az = tgtA[j + 2];
      // who leaves first: the top, and the windward side; a fifth trail in late
      const top = clamp01((Ay - yt) / H);
      const side = clamp01(dir > 0 ? (Ax - xl) / W : (xr - Ax) / W);
      const d = q0 > 0.8 ? 0.24 + (q0 - 0.8) * 0.7 : (q0 * 0.4 + (top * 0.55 + side * 0.45) * 0.6) * 0.3;
      const v = clamp01((u - d) / 0.62);
      if (v === 0) { tgt[j] = Ax; tgt[j + 1] = Ay; tgt[j + 2] = Az; tcol[i] = tcolA[i]; tbig[i] = tbigA[i]; role[i] = roleA[i]; continue; }
      if (v === 1) continue; // tgt already holds the new shape
      const q1 = Q[q + 1], q2 = Q[q + 2], q3 = Q[q + 3];
      // keyframes: 0 old shape, 1 eroded and slumped, 2 blizzard, 3 ribbon, 4 new shape
      const seg = v < 0.2 ? 0 : v < 0.52 ? 1 : v < 0.78 ? 2 : 3;
      let x0, y0, z0, x1, y1, z1, k1x = 0, k1y = 0, k1z = 0, k2x = 0, k2y = 0, k2z = 0, k3x = 0, k3y = 0, k3z = 0;
      if (seg <= 1) {
        if (i >= NS) {
          // the sea heaves up into spray, downwind
          k1x = Ax + dir * (0.2 + q1 * 0.4);
          k1y = Ay - 0.1 - q2 * 0.35;
          k1z = Az;
        } else {
          k1x = Ax + dir * (0.25 + q1 * 0.45) + (ax - Ax) * 0.25;
          k1y = Ay + 0.32 + (Ay < 0.4 ? (0.4 - Ay) * 0.45 : 0);
          k1z = Az + (q3 - 0.5) * 0.9;
        }
      }
      if (seg === 1 || seg === 2) {
        // A gust takes everything, the sea too: every dot is blown outward from the old
        // shape's middle along its own bearing (mostly the way it already faced, so neighbours
        // stay neighbours), over the whole screen and past the camera, drifting with the wind.
        const drift = v - 0.52;
        let ux = Ax - ax, uy = Ay - ay;
        const l = Math.sqrt(ux * ux + uy * uy) || 1;
        ux = ux / l * 0.7 + (q1 - 0.5) * 0.6;
        uy = uy / l * 0.7 + (q3 - 0.5) * 0.6;
        const r = 0.35 + QP[i * 3 + 1] * 0.95 * Math.max(W, H);
        k2z = (q3 - 0.5) * 2.2;
        const reach = (2.6 + k2z) / 2.6;
        k2x = (ax + ux * r) * reach + dir * drift * W * 0.6;
        k2y = (midY + uy * r * 1.05) * reach - drift * H * 0.3;
      }
      if (seg >= 2) {
        // a funnel: a loose, offset first sketch of the new shape that the storm pours into
        k3x = bx - dir * 0.1 * W + (tgt[j] - bx) * 0.65 + (q1 - 0.5) * 0.3;
        k3y = by + entry + (tgt[j + 1] - by) * 0.65 + (q2 - 0.5) * 0.2;
        k3z = tgt[j + 2] * 0.6 + (q3 - 0.5) * 0.7;
      }
      let w;
      if (seg === 0) { w = v / 0.2; x0 = Ax; y0 = Ay; z0 = Az; x1 = k1x; y1 = k1y; z1 = k1z; }
      else if (seg === 1) { w = (v - 0.2) / 0.32; x0 = k1x; y0 = k1y; z0 = k1z; x1 = k2x; y1 = k2y; z1 = k2z; }
      else if (seg === 2) { w = (v - 0.52) / 0.26; x0 = k2x; y0 = k2y; z0 = k2z; x1 = k3x; y1 = k3y; z1 = k3z; }
      else { w = (v - 0.78) / 0.22; x0 = k3x; y0 = k3y; z0 = k3z; x1 = tgt[j]; y1 = tgt[j + 1]; z1 = tgt[j + 2]; }
      w = w * w * (3 - 2 * w);
      const x = x0 + (x1 - x0) * w, y = y0 + (y1 - y0) * w, z = z0 + (z1 - z0) * w;
      // big, slow eddies in flight, strongest mid-storm
      const amp = Math.sin(Math.PI * v) * 0.34;
      tgt[j] = x + Math.sin(y * 1.35 + t * 0.85) * amp;
      tgt[j + 1] = y + Math.sin(z * 1.35 + x * 0.9 + t * 0.7) * amp * 0.7;
      tgt[j + 2] = z + Math.sin(x * 1.35 - t * 0.75) * amp;
      // each dot takes its new colour (and size and role) somewhere in mid-storm, not all at once
      if (v < 0.35 + q0 * 0.3) {
        tcol[i] = tcolA[i];
        tbig[i] = tbigA[i];
        role[i] = roleA[i];
      }
    }
  }

  function frame(t) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const cw = canvas.clientWidth;
    const ch = canvas.clientHeight;
    if (!cw || !ch || (gl && gl.lost)) return;
    if (rich && !reduced && frames++ > 1) {
      IS = 2;
      I0 = 1 - I0;
    } else {
      IS = 1;
      I0 = 0;
    }
    if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
      canvas.width = Math.round(cw * dpr);
      canvas.height = Math.round(ch * dpr);
    }
    const S = cw < 720 ? cw * 0.42 : Math.min(cw, ch) * 0.46;
    scaleS = S;
    const dotK = gl ? Math.max(0.3, Math.min(1.3, dotRef * S / 368)) : 1;
    const nrw = cw < 720;
    narrowLayout = nrw;
    // On the dense path a scene change is a storm of about a screen of scroll.
    const tl = scroll != null ? timeline(scroll, plan, rich ? 0.46 : BLEND) : null;
    if (reduced) {
      // Pixel anchors must use the camera that this stable frame will draw with.
      ox = SCENE_OFFSETS.get(tl ? tl.a : scene.form) || 0;
      if (tl && tl.b && tl.u > 0) ox += ((SCENE_OFFSETS.get(tl.b) || 0) - ox) * tl.u;
    }
    const cxo = cw / 2 + (nrw ? ox * 0.4 : ox) * cw, cyo = nrw ? ch * 0.36 : ch / 2;
    if (anchor) anchorN = { x: (anchor.x - cxo) / S, y: (anchor.y - cyo) / S };
    if (tierPx) tierN = { x: (tierPx.x - cxo) / S, y: (tierPx.y - cyo) / S, w: tierPx.w / S, h: tierPx.h / S };
    else tierN = defaultTier;
    lockN = lockPx ? { x: (lockPx.x - cxo) / S, y: (lockPx.y - cyo) / S, w: lockPx.w / S, h: lockPx.h / S } : null;
    // the side score's room: from the camera centre to a gutter inside the canvas's left edge,
    // which also absorbs the parallax still settling as the camera squares up for the sunrise
    scoreRoom = (cxo - Math.max(24, cw * 0.04)) / S;
    // the screen's edges in scene units, at the depth of the page
    const xl = -cxo / S, xr = (cw - cxo) / S, yt = -cyo / S, yb = (ch - cyo) / S;
    viewL = xl;
    viewR = xr;
    let storm = 0;
    let spec;
    if (tl) {
      spec = build(tl.a, t, tl.pa, tl.ia);
      if (tl.b && tl.u > 0) {
        tgtA.set(tgt);
        tcolA.set(tcol);
        tbigA.set(tbig);
        roleA.set(role);
        const specB = build(tl.b, t, tl.pb, tl.ib, rich ? spec.seaFar + spec.seaDrop * 1000 : null);
        const u = tl.u;
        if (rich) {
          storm = Math.sin(Math.PI * u);
          stormBlend(u, t, xl, xr, yt, yb, tl.ia % 2 ? -1 : 1);
        } else
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
          halo: spec.halo + (specB.halo - spec.halo) * u,
        };
      }
    } else {
      spec = build(scene.form, t, clamp01(scene.phase || 0), 0);
    }
    if (rich && !reduced && !spec.still) {
      // Shapes breathe with the flow, and a few of their dots wander off and back, so the
      // edges stay dusty and alive. Words and figures that must read stay crisp.
      for (let i = I0; i < NS; i += IS) {
        if (role[i] !== 0) continue;
        const j = i * 3;
        const q = Q[i * 5 + 4];
        if (q < spec.halo) {
          // shed dots ride the flow in streams
          const a = 0.015 + (q / Math.max(0.01, spec.halo)) * 0.05;
          flow(tgt[j] * 1.8, tgt[j + 1] * 1.8, tgt[j + 2] * 1.8, t * 0.45, fl);
          tgt[j] += fl[0] * a;
          tgt[j + 1] += fl[1] * a - a * 0.3;
          tgt[j + 2] += fl[2] * a;
        } else {
          // the body breathes as one, in slow waves
          tgt[j] += Math.sin(tgt[j + 1] * 3.2 + t * 0.55) * 0.01;
          tgt[j + 1] += Math.sin(tgt[j] * 3.2 - t * 0.45) * 0.008;
        }
      }
    }
    gust += (storm - gust) * 0.06;
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
      // In a storm the springs stiffen, so the dots actually reach the storm's shapes.
      const k0 = rich ? 0.014 : 0.006, k1 = rich ? 0.01 : 0.006, kg = rich ? gust * 0.038 : 0;
      const damp = rich ? 0.85 - gust * 0.03 : 0.88;
      for (let i = 0; i < N; i++) {
        const ks = role[i] === 1 && rich && kg < 0.01 ? 0.12 : k0 + R[i * 6 + 4] * k1 + kg;
        const j = i * 3;
        const dx = tgt[j] - pos[j];
        const dy = tgt[j + 1] - pos[j + 1];
        const dz = tgt[j + 2] - pos[j + 2];
        vel[j] = (vel[j] + dx * ks) * damp;
        vel[j + 1] = (vel[j + 1] + dy * ks) * damp;
        vel[j + 2] = (vel[j + 2] + dz * ks) * damp;
        pos[j] += vel[j];
        pos[j + 1] += vel[j + 1];
        pos[j + 2] += vel[j + 2];
        if ((rich && gust > 0.05) || dx * dx + dy * dy + dz * dz < 0.02) col[i] = tcol[i];
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
      const jj = col[i] >= 5 || rich ? 0 : jit;
      px[i] = cx + x1 * S * sc + (jj ? Math.sin(t * 2.2 + i) * jj : 0);
      py[i] = cy + y2 * S * sc + (jj ? Math.cos(t * 1.9 + i * 0.7) * jj : 0);
      ps[i] = (0.8 + R[i * 6 + 1] * 1.4) * 1.3 * sc * big[i] * (col[i] >= 5 ? 1.25 : 1) * dotK;
      const dep = 1 - (Math.max(-1.2, Math.min(1.2, z2)) + 1.2) / 2.4;
      pa[i] = col[i] >= 5 ? 1 : rich ? (0.62 + dep * 0.38) * (role[i] === 2 ? 0.65 : 1) * (z2 > 1.2 ? Math.max(0.15, 1 - (z2 - 1.2) / 3) : 1) : 0.22 + dep * 0.78;
    }
    if (gl) {
      // the dots grouped by colour in the 2D path's order (a counting sort)
      const out = glData;
      colStart.fill(0);
      for (let i = 0; i < N; i++) colStart[col[i] + 1]++;
      for (let c = 1; c < 8; c++) colStart[c] += colStart[c - 1];
      for (let i = 0; i < N; i++) {
        const c = col[i];
        let k = colStart[c]++ * GL_STRIDE;
        out[k++] = px[i];
        out[k++] = py[i];
        out[k++] = ps[i];
        out[k++] = pa[i] * AM[c];
        out[k] = c;
      }
      gl.draw(cw, ch, dpr, out, N);
      return;
    }
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
    renderer: gl ? "webgl" : "2d",
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
    // the slot (canvas pixels: centre and size) where the closing lockup is drawn
    setLockup(x, y, w, h) {
      if (x == null ? lockPx === null : lockPx && lockPx.x === x && lockPx.y === y && lockPx.w === w && lockPx.h === h) return;
      lockPx = x == null ? null : { x, y, w, h };
      invalidate();
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      clearTimeout(lostTimer);
      cancelAnimationFrame(raf);
      raf = 0;
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("resize", invalidate);
      document.removeEventListener("visibilitychange", syncActivity);
      if (io) io.disconnect();
      if (gl) gl.dispose();
    },
  };
}
