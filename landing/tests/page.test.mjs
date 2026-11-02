import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");

test("the landing page does not publish the placeholder benchmark scene", () => {
  assert.doesNotMatch(page, /Terminal-Bench 4|data-copy="bench"|bench-scores|\[PAPER URL\]/);
  assert.doesNotMatch(page, /\["sun", 3\]/);
});

test("forced colours get the static story", () => {
  // In forced colours the artwork's dots carry no reliable contrast, so the page takes the
  // same static presentation as reduced motion, and follows the setting when it changes.
  assert.match(page, /const forced = window\.matchMedia\("\(forced-colors: active\)"\);/);
  assert.match(page, /const canAnimate = [^;]*!forced\.matches[^;]*;/, "forced colours turn the animated story off");
  assert.match(page, /forced\.addEventListener\("change", syncPresentation\);/, "a change of the setting re-presents the story");
});
