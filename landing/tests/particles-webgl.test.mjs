import assert from "node:assert/strict";
import test from "node:test";
import { mountParticles } from "../src/scripts/particles.js";

// A WebGL2 context that records what the artwork asks of it: each upload of the point data
// (x, y, size, alpha, palette index per dot) and each draw.
function webgl() {
  const calls = { draws: [], uploads: [] };
  return {
    calls,
    VERTEX_SHADER: 1, FRAGMENT_SHADER: 2, LINK_STATUS: 3, ARRAY_BUFFER: 4, DYNAMIC_DRAW: 5,
    FLOAT: 6, COLOR_BUFFER_BIT: 7, BLEND: 8, ONE: 9, ONE_MINUS_SRC_ALPHA: 10, POINTS: 0,
    createShader: () => ({}), shaderSource() {}, compileShader() {}, deleteShader() {},
    createProgram: () => ({}), attachShader() {}, linkProgram() {}, getProgramParameter: () => true, deleteProgram() {},
    createVertexArray: () => ({}), bindVertexArray() {}, deleteVertexArray() {},
    createBuffer: () => ({}), bindBuffer() {}, deleteBuffer() {},
    enableVertexAttribArray() {}, vertexAttribPointer() {},
    getUniformLocation: () => ({}), uniform2f() {}, uniform1f() {}, uniform3fv() {},
    isContextLost: () => false, getExtension: () => null,
    viewport() {}, clearColor() {}, clear() {}, useProgram() {}, enable() {}, blendFunc() {},
    bufferData() {},
    bufferSubData(_target, _offset, data, start, length) { calls.uploads.push(data.slice(start, start + length)); },
    drawArrays(_mode, _first, count) { calls.draws.push(count); },
  };
}

function environment(t, { size = [1280, 800] } = {}) {
  const names = ["window", "document", "IntersectionObserver", "requestAnimationFrame", "cancelAnimationFrame"];
  const originals = names.map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]);
  const queue = new Map();
  let nextId = 1;
  let observer;
  const listeners = () => {
    const map = new Map();
    return {
      addEventListener(name, fn) { if (!map.has(name)) map.set(name, new Set()); map.get(name).add(fn); },
      removeEventListener(name, fn) { map.get(name)?.delete(fn); },
      dispatch(name, event = { preventDefault() {} }) { for (const fn of map.get(name) ?? []) fn(event); },
    };
  };
  // the offscreen canvas the shapes are sampled from: an opaque band where the shape is drawn
  const sampling = () => ({
    setTransform() {}, clearRect() {}, beginPath() {}, arc() {}, arcTo() {}, moveTo() {}, lineTo() {},
    quadraticCurveTo() {}, closePath() {}, stroke() {}, fill() {}, fillRect() {}, strokeText() {}, fillText() {},
    measureText: (text) => ({ width: text.length * 80 }),
    getImageData(_x, _y, width, height) {
      const data = new Uint8ClampedArray(width * height * 4);
      for (let y = 110; y < 190; y++) for (let x = 120; x < 780; x++) data[(y * width + x) * 4 + 3] = 255;
      return { data };
    },
  });
  const gl = webgl();
  const asked = { twoD: 0 }; // how often the artwork asked the canvas for a 2D context
  const canvas = {
    clientWidth: size[0], clientHeight: size[1], width: 0, height: 0,
    ...listeners(),
    getContext: (type) => (type === "webgl2" ? gl : type === "2d" ? (asked.twoD++, null) : null),
  };
  Object.assign(globalThis, {
    window: { ...listeners(), innerWidth: size[0], devicePixelRatio: 1 },
    document: {
      ...listeners(), hidden: false, fonts: { load: () => new Promise(() => {}) },
      createElement: () => {
        const ctx = sampling();
        return { width: 0, height: 0, ...listeners(), getContext: (type) => (type === "webgl2" ? webgl() : ctx) };
      },
    },
    IntersectionObserver: class {
      constructor(callback) { this.callback = callback; observer = this; }
      observe() {}
      disconnect() {}
    },
    requestAnimationFrame(callback) { const id = nextId++; queue.set(id, callback); return id; },
    cancelAnimationFrame(id) { queue.delete(id); },
  });
  const arts = [];
  t.after(() => {
    for (const art of arts) art.destroy();
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  return {
    gl, asked, canvas,
    mount(options) { const art = mountParticles(canvas, options); arts.push(art); return art; },
    intersect(isIntersecting) { observer.callback([{ isIntersecting }]); },
    flush(now) {
      const callbacks = [...queue.values()];
      queue.clear();
      for (const callback of callbacks) callback(now);
    },
  };
}

const PLAN = [["hero", 0.82], ["alone", 1.5], ["swarm", 1.5], ["robot", 3.6], ["sun", 3], ["end", 1]];

test("with WebGL every dot of the budget is drawn in one call per frame, and no 2D context is taken", (t) => {
  const env = environment(t);
  const art = env.mount({ count: 800, glCount: 12000, plan: PLAN, scores: ["60", "80"] });
  assert.equal(art.renderer, "webgl");
  env.intersect(true);
  env.flush(0);
  env.flush(16);
  assert.deepEqual(env.gl.calls.draws, [12000, 12000]);
  assert.equal(env.gl.calls.uploads.at(-1).length, 12000 * 5, "x, y, size, alpha and colour for each dot");
  assert.equal(env.asked.twoD, 0, "a canvas that hands out a 2D context can never give WebGL");
});

test("with WebGL the artwork stops drawing offscreen", (t) => {
  const env = environment(t);
  env.mount({ count: 800, glCount: 12000, plan: PLAN });
  env.intersect(true);
  env.flush(0);
  env.intersect(false);
  env.flush(16);
  assert.equal(env.gl.calls.draws.length, 1);
});

test("with WebGL a storm between scenes sweeps the whole screen, within the budget and without NaN", (t) => {
  const env = environment(t);
  const art = env.mount({ count: 800, glCount: 12000, plan: PLAN, scores: ["60", "80"] });
  env.intersect(true);
  // settle on the clock, then cross the change to the swarm, a screen of scroll
  art.setScroll(1.5);
  for (let k = 0; k < 120; k++) env.flush(k * 16);
  const spread = (data) => {
    const xs = [];
    for (let i = 0; i < data.length; i += 5) if (data[i] >= 0 && data[i] <= 1280) xs.push(data[i]);
    xs.sort((a, b) => a - b);
    return xs[Math.floor(xs.length * 0.95)] - xs[Math.floor(xs.length * 0.05)];
  };
  const atRest = spread(env.gl.calls.uploads.at(-1));
  let widest = 0;
  for (let k = 0; k <= 80; k++) {
    art.setScroll(1.86 + k * 0.012);
    env.flush((120 + k) * 16);
    const upload = env.gl.calls.uploads.at(-1);
    for (const value of upload) assert.ok(Number.isFinite(value), "no dot is lost to NaN");
    widest = Math.max(widest, spread(upload));
  }
  assert.ok(env.gl.calls.draws.every((count) => count === 12000));
  assert.ok(widest > 1280 * 0.8, `mid-storm the dots span the screen (${widest.toFixed(0)} px)`);
  assert.ok(widest > atRest, "wider than the settled scene");
});

test("on a phone the closing scene's sea sinks below the screen, clear of the copy", (t) => {
  const env = environment(t, { size: [390, 844] });
  const art = env.mount({ count: 800, glCount: 12000, plan: PLAN, scores: ["60", "80"] });
  env.intersect(true);
  art.setScroll(11.2);
  for (let k = 0; k < 400; k++) env.flush(k * 16);
  const data = env.gl.calls.uploads.at(-1);
  let below = 0;
  for (let i = 0; i < data.length; i += 5) {
    assert.ok(Number.isFinite(data[i]) && Number.isFinite(data[i + 1]));
    if (data[i + 1] > 844) below++;
  }
  assert.ok(below / 12000 > 0.15, `the sea's dots (${below}) are below the screen`);
});

test("with WebGL a lost context pauses drawing and resumes when restored", (t) => {
  const env = environment(t);
  env.mount({ count: 800, glCount: 12000, plan: PLAN });
  env.intersect(true);
  env.flush(0);
  env.canvas.dispatch("webglcontextlost");
  env.flush(16);
  env.flush(32);
  assert.equal(env.gl.calls.draws.length, 1, "nothing is drawn while the context is lost");
  env.canvas.dispatch("webglcontextrestored");
  env.flush(48);
  assert.equal(env.gl.calls.draws.length, 2);
});

test("with WebGL a context that is not restored hands the page its static story", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const env = environment(t);
  let unavailable = 0;
  env.mount({ count: 800, glCount: 12000, plan: PLAN, onUnavailable: () => unavailable++ });
  env.intersect(true);
  env.flush(0);
  env.canvas.dispatch("webglcontextlost");
  t.mock.timers.tick(2900);
  assert.equal(unavailable, 0, "a quick restore is still possible");
  t.mock.timers.tick(200);
  assert.equal(unavailable, 1);
});

test("with WebGL the closing lockup fills its slot and holds still", (t) => {
  const env = environment(t);
  const art = env.mount({ count: 800, glCount: 12000, plan: PLAN, scores: ["60", "80"] });
  env.intersect(true);
  const slot = { x: 640, y: 200, w: 600, h: 125 };
  art.setLockup(slot.x, slot.y, slot.w, slot.h);
  art.setScroll(11.2);
  for (let k = 0; k < 600; k++) env.flush(k * 16);
  const inSlot = (data) => {
    const dots = [];
    for (let i = 0; i < data.length; i += 5) {
      const x = data[i], y = data[i + 1];
      if (Math.abs(x - slot.x) <= slot.w / 2 + 2 && Math.abs(y - slot.y) <= slot.h / 2 + 2) dots.push([x, y]);
    }
    return dots;
  };
  const before = inSlot(env.gl.calls.uploads.at(-1));
  env.flush(600 * 16);
  const after = inSlot(env.gl.calls.uploads.at(-1));
  assert.ok(before.length > 1000, "the lockup is drawn in its slot");
  assert.equal(after.length, before.length);
  let drift = 0;
  for (let k = 0; k < before.length; k++) drift = Math.max(drift, Math.hypot(after[k][0] - before[k][0], after[k][1] - before[k][1]));
  assert.ok(drift < 0.5, `the settled lockup holds still (moved ${drift.toFixed(2)} px)`);
  const xs = before.map(([x]) => x);
  assert.ok(Math.max(...xs) - Math.min(...xs) > slot.w * 0.8, "the lockup spans its slot");
});
