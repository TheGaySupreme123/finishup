import assert from "node:assert/strict";
import test from "node:test";
import { mountParticles } from "../src/scripts/particles.js";

function environment(t, { opaqueSamples = false, size = [1024, 768] } = {}) {
  const names = ["window", "document", "IntersectionObserver", "requestAnimationFrame", "cancelAnimationFrame"];
  const originals = names.map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]);
  const queue = new Map();
  const controllers = [];
  const texts = [];
  let nextId = 1;
  let observer;
  let finishFonts;
  const fonts = new Promise((resolve) => { finishFonts = resolve; });
  const eventTarget = () => {
    const listeners = new Map();
    return {
      addEventListener(name, fn) {
        if (!listeners.has(name)) listeners.set(name, new Set());
        listeners.get(name).add(fn);
      },
      removeEventListener(name, fn) { listeners.get(name)?.delete(fn); },
      dispatch(name, event = {}) { for (const fn of listeners.get(name) ?? []) fn(event); },
      listenerCount() { return [...listeners.values()].reduce((sum, set) => sum + set.size, 0); },
    };
  };
  const context = (main = false) => ({
    frames: 0,
    draws: [],
    tierDraws: [],
    inkDraws: [],
    setTransform() {},
    clearRect() { if (main) { this.frames++; this.draws = []; this.tierDraws = []; this.inkDraws = []; } },
    beginPath() {}, arc() {}, arcTo() {}, moveTo() {}, lineTo() {},
    quadraticCurveTo() {}, closePath() {}, stroke() {}, fill() {}, fillRect() {},
    strokeText() {},
    fillText(text) { texts.push(text); },
    measureText(text) { return { width: text.length * 80 }; },
    getImageData(_x, _y, width, height) {
      const data = new Uint8ClampedArray(width * height * 4);
      // A deterministic nonempty word mask exercises sampled tier targets instead of scatter.
      if (opaqueSamples) {
        for (let y = 110; y < 190; y++) {
          for (let x = 120; x < 780; x++) data[(y * width + x) * 4 + 3] = 255;
        }
      }
      return { data };
    },
    drawImage(sprite, ...geometry) {
      if (main) {
        this.draws.push(geometry);
        if (sprite.getContext("2d").fillStyle === "#C48A0E") this.tierDraws.push(geometry);
        if (sprite.getContext("2d").fillStyle === "#064E3B") this.inkDraws.push(geometry);
      }
    },
  });
  const ctx = context(true);
  const canvas = { clientWidth: size[0], clientHeight: size[1], width: 0, height: 0, getContext: () => ctx };
  const win = { ...eventTarget(), innerWidth: size[0], devicePixelRatio: 1 };
  const doc = {
    ...eventTarget(), hidden: false, fonts: { load: () => fonts },
    createElement: () => {
      const ctx = context();
      return { width: 0, height: 0, getContext: () => ctx };
    },
  };
  Object.assign(globalThis, {
    window: win,
    document: doc,
    IntersectionObserver: class {
      constructor(callback) { this.callback = callback; this.disconnected = false; observer = this; }
      observe(target) { this.target = target; }
      disconnect() { this.disconnected = true; }
    },
    requestAnimationFrame(callback) { const id = nextId++; queue.set(id, callback); return id; },
    cancelAnimationFrame(id) { queue.delete(id); },
  });
  t.after(() => {
    for (const controller of controllers) controller.destroy();
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  return {
    queue, ctx, canvas, win, doc, texts, finishFonts,
    get observer() { return observer; },
    mount(options = {}) {
      const art = mountParticles(canvas, { count: 800, ...options });
      controllers.push(art);
      return art;
    },
    intersect(isIntersecting) { observer.callback([{ target: canvas, isIntersecting }]); },
    flush(now) {
      const callbacks = [...queue.values()];
      queue.clear();
      for (const callback of callbacks) callback(now);
    },
  };
}

test("offscreen and hidden documents stop rendering and resume without advancing hidden time", (t) => {
  const env = environment(t);
  env.mount();
  assert.equal(env.queue.size, 0);
  env.intersect(true);
  env.flush(0);
  assert.equal(env.ctx.frames, 1);
  assert.equal(env.queue.size, 1);
  env.intersect(false);
  assert.equal(env.queue.size, 0);
  env.doc.hidden = true;
  env.doc.dispatch("visibilitychange");
  env.intersect(true);
  assert.equal(env.queue.size, 0);
  env.doc.hidden = false;
  env.doc.dispatch("visibilitychange");
  env.flush(100000);
  assert.equal(env.ctx.frames, 2);
  assert.deepEqual(env.texts, ["work"]);
  env.flush(103201);
  assert.deepEqual(env.texts, ["work", "code"]);
});

test("a WebGL budget falls back to the 2D budget where WebGL is unavailable", (t) => {
  const env = environment(t);
  const art = env.mount({ count: 800, glCount: 50000 });
  assert.equal(art.renderer, "2d");
  env.intersect(true);
  env.flush(0);
  assert.equal(env.ctx.frames, 1);
  assert.equal(env.ctx.draws.length, 800, "every dot of the 2D budget, drawn on the 2D canvas");
});

test("destroy cancels pending work and cannot be revived by font or observer callbacks", async (t) => {
  const env = environment(t);
  const art = env.mount();
  env.intersect(true);
  const staleFrame = [...env.queue.values()][0];
  art.destroy();
  art.destroy();
  assert.equal(env.queue.size, 0);
  assert.equal(env.win.listenerCount(), 0);
  assert.equal(env.doc.listenerCount(), 0);
  assert.equal(env.observer.disconnected, true);
  env.finishFonts([]);
  await Promise.resolve();
  env.intersect(true);
  staleFrame(1000);
  art.setScroll(2);
  assert.equal(env.queue.size, 0);
  assert.equal(env.ctx.frames, 0);
});

test("reduced motion renders stable state changes without a continuous animation loop", (t) => {
  const env = environment(t);
  const art = env.mount({ reducedMotion: true });
  env.intersect(true);
  env.flush(0);
  const initial = env.ctx.draws;
  assert.equal(env.queue.size, 0);
  art.setScene("hero", 0);
  assert.equal(env.queue.size, 0);
  art.setScene("swarm", 0.5);
  env.flush(50000);
  assert.equal(env.queue.size, 0);
  art.setScene("hero", 0);
  env.flush(100000);
  assert.deepEqual(env.ctx.draws, initial);
  assert.equal(env.ctx.frames, 3);
  assert.deepEqual(env.texts, ["work"]);
  env.win.dispatch("resize");
  env.flush(200000);
  assert.equal(env.ctx.frames, 4);
  assert.equal(env.queue.size, 0);
});

// The page supplies the benchmark figures (BENCH in index.astro, marked PLACEHOLDER until
// the owner fills them in); the artwork never falls back to figures of its own.
test("the benchmark artwork draws no score unless the page supplies one", (t) => {
  const env = environment(t);
  const art = env.mount({ reducedMotion: true });
  art.setScene("sun", 0.75);
  env.intersect(true);
  env.flush(0);
  assert.deepEqual(env.texts, ["AI-powered"]);
});

test("supplied benchmark scores count up from the first stop to the second", (t) => {
  const env = environment(t);
  const art = env.mount({ scores: ["60", "80"] });
  env.intersect(true);
  for (const [phase, now] of [[0.25, 0], [0.5, 1000], [0.75, 2000]]) {
    art.setScene("sun", phase);
    env.flush(now);
  }
  // The tier word arrives with the second stop, at the middle of the count.
  assert.deepEqual(env.texts, ["60%", "70%", "AI-powered", "80%"]);
});

test("reduced motion shows each stop's own score with no figures in between", (t) => {
  const env = environment(t);
  const art = env.mount({ reducedMotion: true, scores: ["60", "80"] });
  env.intersect(true);
  for (const [phase, now] of [[0.25, 0], [0.45, 1000], [0.5, 2000], [0.55, 3000], [0.75, 4000]]) {
    art.setScene("sun", phase);
    env.flush(now);
    assert.equal(env.queue.size, 0, "each stable state renders once, with no animation loop");
  }
  assert.deepEqual(env.texts, ["60%", "80%", "AI-powered"]);
});

test("benchmark scores render only while the artwork is visible", (t) => {
  const env = environment(t);
  const art = env.mount({ scores: ["60", "80"] });
  art.setScene("sun", 0.5);
  assert.equal(env.queue.size, 0, "nothing is scheduled before the observer reports the canvas");
  env.intersect(true);
  env.flush(0);
  assert.deepEqual(env.texts, ["70%", "AI-powered"]);
  env.intersect(false);
  assert.equal(env.queue.size, 0, "hiding the canvas cancels the pending frame");
  art.setScene("sun", 0.75);
  assert.equal(env.queue.size, 0);
  assert.deepEqual(env.texts, ["70%", "AI-powered"]);
});

test("review artwork can leave the tier label to readable page text", (t) => {
  const env = environment(t);
  const art = env.mount({ reducedMotion: true, drawTier: false });
  art.setScene("sun", 0.75);
  env.intersect(true);
  env.flush(0);
  assert.deepEqual(env.texts, []);
  assert.equal(env.ctx.frames, 1);
});

test("clearing a tier anchor restores the default position", (t) => {
  const env = environment(t, { opaqueSamples: true });
  const art = env.mount({ reducedMotion: true });
  art.setScene("sun", 0.75);
  env.intersect(true);
  env.flush(0);
  const initial = env.ctx.draws;
  art.setTier(800, 480, 250, 50);
  env.flush(1000);
  assert.notDeepEqual(env.ctx.draws, initial);
  art.setTier(null);
  env.flush(2000);
  assert.deepEqual(env.ctx.draws, initial);
  assert.equal(env.queue.size, 0);
});

test("reduced tier particles use the final camera on the first render and unchanged resize", (t) => {
  const env = environment(t, { opaqueSamples: true });
  const art = env.mount({ reducedMotion: true });
  art.setTier(800, 480, 250, 50);
  art.setScene("sun", 0.75);
  env.intersect(true);
  env.flush(0);
  const first = env.ctx.draws;
  assert.equal(env.ctx.tierDraws.length, 440);
  for (const [x, y, w, h] of env.ctx.tierDraws) {
    assert.ok(x >= 675 - w && x + w <= 925 + w, "tier particle stays in the horizontal copy slot");
    assert.ok(y >= 455 - h && y + h <= 505 + h, "tier particle stays in the vertical copy slot");
  }
  env.win.dispatch("resize");
  env.flush(1000);
  assert.deepEqual(env.ctx.draws, first);
  assert.equal(env.queue.size, 0);

  art.setScene("robot", 0.5);
  env.flush(2000);
  art.setScene("sun", 0.75);
  env.flush(3000);
  assert.deepEqual(env.ctx.draws, first, "returning from another camera offset preserves the tier slot");

  art.setScroll(10.32); // Blend the sun into the closing scene, with a different final offset.
  env.flush(4000);
  const blended = env.ctx.draws;
  assert.ok(env.ctx.tierDraws.length > 0);
  env.win.dispatch("resize");
  env.flush(5000);
  assert.deepEqual(env.ctx.draws, blended, "a blended camera also renders stable pixel anchors");
});

for (const reducedMotion of [false, true]) {
  test(`the artwork draws decimal scores verbatim at both stops (reduced motion: ${reducedMotion})`, (t) => {
    const env = environment(t);
    const art = env.mount({ reducedMotion, scores: ["62.4", "81.7"] });
    env.intersect(true);
    art.setScene("sun", 0.25);
    env.flush(0);
    art.setScene("sun", 0.75);
    env.flush(1000);
    assert.deepEqual(env.texts.filter((text) => text.endsWith("%")), ["62.4%", "81.7%"]);
  });
}

test("the count-up keeps the supplied precision and samples a bounded set of figures", (t) => {
  const env = environment(t);
  const art = env.mount({ scores: ["62.4", "81.7"] });
  env.intersect(true);
  for (let k = 0; k <= 400; k++) {
    art.setScene("sun", 0.35 + (0.3 * k) / 400);
    env.flush(k * 20);
  }
  const scores = env.texts.filter((text) => text.endsWith("%"));
  assert.equal(scores[0], "62.4%");
  assert.equal(scores.at(-1), "81.7%");
  for (const score of scores) assert.match(score, /^\d+\.\d%$/, "every figure keeps one decimal");
  assert.ok(scores.length <= 41, `a bounded count-up (${scores.length} figures sampled)`);
});

// The engine's scale and camera for a canvas (see frame() in particles.js): the ink dots
// above the horizon in the sunrise are the score's.
function scoreDots(env, [w, h]) {
  const S = w < 720 ? w * 0.42 : Math.min(w, h) * 0.46;
  const cy = w < 720 ? h * 0.36 : h / 2;
  return env.ctx.inkDraws.filter(([, y, , size]) => y + size / 2 < cy + 0.4 * S);
}

// The engine keeps the side score this far inside the canvas's left edge.
const gutter = ([w]) => Math.max(24, w * 0.04);

for (const size of [[768, 1024], [720, 900], [820, 1180], [900, 1000], [1024, 1366], [1024, 768], [1440, 900], [390, 844]]) {
  test(`the score keeps its gutter inside a ${size[0]}x${size[1]} canvas at both stops`, (t) => {
    const env = environment(t, { opaqueSamples: true, size });
    const art = env.mount({ reducedMotion: true, count: 5500, scores: ["60", "80"] });
    env.intersect(true);
    for (const [phase, now] of [[0.25, 0], [0.75, 1000]]) {
      art.setScene("sun", phase);
      env.flush(now);
      const dots = scoreDots(env, size);
      assert.ok(dots.length > 100, "the score is drawn");
      for (const [x, , w] of dots) {
        assert.ok(x >= gutter(size) - 3 && x + w <= size[0], `dot at ${x.toFixed(1)} keeps the ${gutter(size)}px gutter inside 0..${size[0]}`);
      }
    }
  });
}

// A landscape canvas keeps the side score at its full size: at the same scale (the canvas
// height sets it) the score spans the same width on a 1440 and a 2560 wide canvas, and
// that span is the full-size figure's (0.6 scene units per sample unit).
for (const size of [[1440, 900], [2560, 900]]) {
  test(`a ${size[0]}x${size[1]} canvas keeps the side score at its full size`, (t) => {
    const env = environment(t, { opaqueSamples: true, size });
    const art = env.mount({ reducedMotion: true, count: 5500, scores: ["60", "80"] });
    env.intersect(true);
    art.setScene("sun", 0.25);
    env.flush(0);
    const xs = scoreDots(env, size).map(([x, , w]) => x + w / 2);
    // The test mask spans sample x 120..778 of 900, so walked dots span at most 658/450 units.
    const span = Math.max(...xs) - Math.min(...xs);
    const full = 0.6 * (658 / 450) * Math.min(...size) * 0.46;
    assert.ok(span > full * 0.85 && span <= full + 1, `span ${span.toFixed(1)} of a full-size ${full.toFixed(1)}`);
  });
}

// The dotted word's slot on the built page at the second stop (canvas px: left, top, width,
// height) and the top of "Read the full paper" below it, measured in Chromium.
const PAGE = {
  "1920x1080": { slot: [1204, 561, 620, 73], paperTop: 654 },
  "768x1024": { slot: [102, 462, 620, 42], paperTop: 524 },
  "700x1000": { slot: [16, 842, 620, 44], paperTop: 906 },
  "390x844": { slot: [16, 689, 358, 41], paperTop: 750 },
};

// With motion on, the pointer at either edge must not swing the sunrise's flat words out of
// place: the score keeps its gutter and the dotted word stays in its slot, above the link.
for (const [size, side] of [[[1920, 1080], "left"], [[768, 1024], "left"], [[768, 1024], "right"], [[700, 1000], "right"], [[390, 844], "right"]]) {
  test(`with motion and the pointer at the ${side} edge, a ${size[0]}x${size[1]} sunrise keeps its words in place`, (t) => {
    const { slot: [sx, sy, sw, sh], paperTop } = PAGE[size.join("x")];
    const env = environment(t, { opaqueSamples: true, size });
    const art = env.mount({ count: size[0] < 720 ? 2600 : 5500, scores: ["60", "80"] });
    art.setTier(sx + sw / 2, sy + sh / 2, sw, sh);
    env.intersect(true);
    env.win.dispatch("pointermove", { clientX: side === "left" ? 0 : size[0] - 1 });
    art.setScene("sun", 0.75);
    // Frames 200 ms apart: the springs settle well within 200 frames, and frames 200..400
    // (40 s to 80 s) cover both peaks of the ambient sway.
    for (let k = 0; k < 400; k++) {
      env.flush(k * 200);
      if (k < 200) continue;
      for (const [x, , w] of scoreDots(env, size)) {
        assert.ok(x >= gutter(size) - 4 && x + w <= size[0], `frame ${k}: score dot at ${x.toFixed(1)} keeps the gutter`);
      }
      assert.ok(env.ctx.tierDraws.length > 100, "the dotted word is drawn");
      for (const [x, y, w, h] of env.ctx.tierDraws) {
        assert.ok(x >= sx - w - 2 && x + w <= sx + sw + w + 2, `frame ${k}: word dot at x ${x.toFixed(1)} stays in the slot ${sx}..${sx + sw}`);
        assert.ok(y >= sy - h - 2 && y + h <= Math.min(sy + sh + h + 2, paperTop), `frame ${k}: word dot at y ${y.toFixed(1)} stays in the slot, above the link`);
      }
    }
  });
}
