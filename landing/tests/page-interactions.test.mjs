import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import test from "node:test";
import vm from "node:vm";

const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");
const script = stripTypeScriptTypes(page.match(/<script>\s*([\s\S]*?)<\/script>/)[1]
  .replace(/import \{ mountParticles \} from [^;]+;/, "")
  .replaceAll("import.meta.env.DEV", "false"));

// Run the actual page controller with controlled layout, events and timers. Artwork is
// stubbed here; its renderers and destruction are exercised by the particle tests.
function environment({ fits = true } = {}) {
  class Events {
    listeners = new Map();
    addEventListener(name, fn) {
      if (!this.listeners.has(name)) this.listeners.set(name, new Set());
      this.listeners.get(name).add(fn);
    }
    removeEventListener(name, fn) { this.listeners.get(name)?.delete(fn); }
    async dispatch(name, event = {}) {
      await Promise.all([...this.listeners.get(name) ?? []].map((fn) => fn(event)));
    }
  }
  class Element extends Events {
    hidden = false;
    inert = false;
    dataset = {};
    attributes = new Map();
    classes = new Set();
    style = { removeProperty() {} };
    classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
      toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name),
    };
    setAttribute(name, value) { this.attributes.set(name, value); }
    removeAttribute(name) { this.attributes.delete(name); }
    contains(el) { return el === this || el?.parent === this; }
    closest() { return null; }
    querySelector() { return null; }
    getBoundingClientRect() { return { top: 100, bottom: 500, left: 32, right: 700, width: 668, height: 400 }; }
  }
  const ids = Object.fromEntries([
    "particles", "story", "motion-toggle", "main-content", "story-plan", "bench-scores",
    "bench-with", "toast", "toast-title", "toast-sub", "toast-close",
  ].map((id) => [id, new Element()]));
  ids["story-plan"].textContent = JSON.stringify([["hero", 0.82], ["alone", 1.5], ["swarm", 1.5], ["robot", 3.6], ["sun", 3], ["end", 1]]);
  ids["bench-scores"].textContent = '["60", "80"]';
  ids.particles.clientHeight = 800;
  ids.particles.getBoundingClientRect = () => ({ top: 0, bottom: 800, left: 0, right: 1280 });
  ids.story.dataset.screens = "12";
  ids.story.querySelector = () => new Element();
  const content = new Element();
  content.getBoundingClientRect = () => ({ top: 100, bottom: fits ? 500 : 850, left: 32, right: 700 });
  ids.story.querySelectorAll = () => [content];
  ids.toast.hidden = true;
  ids["toast-close"].parent = ids.toast;
  const toastLink = new Element();
  toastLink.parent = ids.toast;
  const setup = new Element();
  setup.dataset.prompt = "Install FinishUP";
  const copies = ["hero", "alone", "swarm", "robot1", "robot2", "robot3", "bench", "end"].map((copy) => {
    const el = new Element();
    el.dataset.copy = copy;
    return el;
  });
  let finishFonts;
  const doc = Object.assign(new Events(), {
    activeElement: setup,
    fonts: { ready: new Promise((resolve) => { finishFonts = resolve; }) },
    getElementById: (id) => ids[id],
    querySelectorAll: (selector) => selector === ".copy" ? copies : [setup],
    querySelector: () => null,
  });
  const queries = new Map();
  const timers = new Map();
  const frames = new Map();
  let nextId = 0;
  let activeArt = 0;
  const win = Object.assign(new Events(), {
    scrollY: 0,
    matchMedia(query) {
      const media = Object.assign(new Events(), { matches: false });
      queries.set(query, media);
      return media;
    },
    setTimeout(fn) { const id = ++nextId; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  const context = vm.createContext({
    window: win, document: doc, innerWidth: 1280, innerHeight: 800,
    HTMLElement: Element, CanvasRenderingContext2D: class {}, CSS: { supports: () => true },
    navigator: { clipboard: { writeText: async () => {} } },
    requestAnimationFrame(fn) { const id = ++nextId; frames.set(id, fn); return id; },
    cancelAnimationFrame(id) { frames.delete(id); },
    mountParticles() {
      activeArt++;
      return { renderer: "webgl", setScroll() {}, setLockup() {}, destroy() { activeArt--; } };
    },
  });
  vm.runInContext(script, context, { timeout: 1000 });
  return {
    ids, doc, win, setup, toastLink, copies, queries, timers, finishFonts,
    get activeArt() { return activeArt; },
    setFits(value) { fits = value; },
    expireTimers() {
      const callbacks = [...timers.values()];
      timers.clear();
      for (const fn of callbacks) fn();
    },
  };
}

test("a hovered toast survives focus leaving, and expires only after hover and focus leave", async () => {
  const env = environment();
  await env.setup.dispatch("click");
  assert.equal(env.ids.toast.hidden, false);
  await env.ids.toast.dispatch("pointerenter");
  env.doc.activeElement = env.toastLink;
  await env.ids.toast.dispatch("focusin");
  env.doc.activeElement = env.setup;
  await env.ids.toast.dispatch("focusout", { relatedTarget: env.setup });
  assert.equal(env.timers.size, 0, "focus leaving cannot start a timer while still hovered");
  env.expireTimers();
  assert.equal(env.ids.toast.hidden, false);
  env.doc.activeElement = env.toastLink;
  await env.ids.toast.dispatch("pointerleave");
  assert.equal(env.timers.size, 0, "leaving with the pointer cannot hide a focused link");
  env.doc.activeElement = env.setup;
  await env.ids.toast.dispatch("focusout", { relatedTarget: env.setup });
  assert.equal(env.timers.size, 1);
  env.expireTimers();
  assert.equal(env.ids.toast.hidden, true);
});

test("pause destroys the artwork and exposes every scene; play restores animation", async () => {
  const env = environment();
  const toggle = env.ids["motion-toggle"];
  assert.equal(toggle.hidden, false);
  assert.equal(env.activeArt, 1);
  await toggle.dispatch("click");
  assert.equal(env.activeArt, 0);
  assert.equal(env.ids.story.classList.contains("animated"), false);
  assert.equal(toggle.attributes.get("aria-label"), "Play animation");
  assert.ok(env.copies.every((el) => !el.inert && !el.attributes.has("aria-hidden")));
  await env.win.dispatch("resize");
  await env.win.dispatch("pagehide");
  await env.win.dispatch("pageshow", { persisted: true });
  assert.equal(env.activeArt, 0, "resize and history restoration preserve the visitor's pause");
  await toggle.dispatch("click");
  assert.equal(env.activeArt, 1);
  assert.equal(env.ids.story.classList.contains("animated"), true);
  assert.equal(toggle.attributes.get("aria-label"), "Pause animation");
});

test("copy that cannot fit uses static flow and animation returns when room is available", async () => {
  const env = environment({ fits: false });
  assert.equal(env.activeArt, 0, "do not mount artwork for a clipped story");
  assert.equal(env.ids.story.classList.contains("animated"), false);
  assert.equal(env.ids["motion-toggle"].hidden, true);
  env.setFits(true);
  await env.win.dispatch("resize");
  assert.equal(env.activeArt, 1);
  env.setFits(false);
  env.finishFonts();
  await Promise.resolve();
  assert.equal(env.activeArt, 0, "a font load that makes copy overflow also switches to static flow");
});

test("reduced motion and forced colours keep animation off regardless of the play control", async () => {
  for (const query of ["(prefers-reduced-motion: reduce)", "(forced-colors: active)"]) {
    const env = environment();
    const media = env.queries.get(query);
    media.matches = true;
    await media.dispatch("change");
    assert.equal(env.activeArt, 0);
    assert.equal(env.ids["motion-toggle"].hidden, true);
    media.matches = false;
    await media.dispatch("change");
    assert.equal(env.activeArt, 1);
  }
});
