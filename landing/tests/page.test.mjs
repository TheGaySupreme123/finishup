import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");
const artwork = readFileSync(new URL("../src/scripts/particles.js", import.meta.url), "utf8");
const frontmatter = page.split(/^---$/m)[1] ?? "";
const benchScene = page.match(/<div class="copy side" data-copy="bench">[\s\S]*?\n\s*<\/div>\n\s*<\/div>/)?.[0] ?? "";

// What the benchmark scene was restored with. The scores and paper link are stand-ins; the
// model and suite are fill-ins from the run too. If any of them is still on the page, the
// PLACEHOLDER marker must be as well. (Should the model or suite turn out to be the real run's,
// confirm it by removing it from this list, not by removing the marker.)
const STAND_INS = { model: ["GPT 6.1 Sol"], suite: ["DeepSWE"], scores: [60, 80], paper: ["[PAPER URL]"] };

// A frontmatter constant, its value evaluated as the JavaScript literal it is (so a stand-in
// is caught however it is written), and the comment lines directly above it.
function declaration(name) {
  const found = [...frontmatter.matchAll(new RegExp(`^const ${name} = ([\\s\\S]*?);$`, "gm"))];
  assert.equal(found.length, 1, `${name} is declared once in the page frontmatter`);
  const value = vm.runInNewContext(`(${found[0][1]})`, Object.create(null), { timeout: 100 });
  const lines = frontmatter.slice(0, found[0].index).split("\n");
  lines.pop();
  let comment = "";
  while (lines.length && lines.at(-1).startsWith("//")) comment = `${lines.pop()}\n${comment}`;
  return { value, comment };
}

test("the benchmark scene reads every figure from the one BENCH declaration", () => {
  assert.ok(benchScene, "the benchmark scene is on the page");
  const { value } = declaration("BENCH");
  assert.equal(value.scores.length, 2, "two stops: Codex alone, then with FinishUP");
  // No percentage is written into the page or the artwork by hand: the scene's figures are
  // rendered from BENCH, so replacing them there replaces them everywhere.
  assert.doesNotMatch(page, /\d+\s*%/, "no literal percentage in the page");
  assert.doesNotMatch(artwork, /\d+\s*%/, "no literal percentage in the artwork");
  assert.match(page, /id="bench-scores" set:html=\{JSON\.stringify\(BENCH\.scores\)\}/, "the artwork's figures come from BENCH");
});

test("the final benchmark figures are page text, outside the canvas and any live region", () => {
  for (const index of [0, 1]) {
    assert.ok(benchScene.includes(`{BENCH.scores[${index}]}%`), `score ${index} is written out in the scene's text`);
  }
  assert.doesNotMatch(benchScene, /aria-live/, "the figures are never announced as they change");
  assert.match(page, /<canvas id="particles" aria-hidden="true">/, "the counting artwork stays hidden from screen readers");
});

test("stand-in benchmark figures and paper link cannot ship unmarked", () => {
  const bench = declaration("BENCH");
  const stale = [
    ...(STAND_INS.model.includes(String(bench.value.model).trim()) ? [`model ${bench.value.model}`] : []),
    ...(STAND_INS.suite.includes(String(bench.value.suite).trim()) ? [`suite ${bench.value.suite}`] : []),
    ...bench.value.scores.filter((score) => STAND_INS.scores.includes(Number(score))).map((score) => `score ${score}`),
  ];
  if (stale.length) {
    assert.match(bench.comment, /PLACEHOLDER BENCHMARK NUMBERS/, `BENCH still holds ${stale.join(", ")}: keep its PLACEHOLDER marker`);
    assert.match(benchScene, /PLACEHOLDER BENCHMARK NUMBERS/, "the scene markup points at the PLACEHOLDER figures");
  }
  const paper = declaration("PAPER_URL");
  if (STAND_INS.paper.includes(String(paper.value).trim())) {
    assert.match(paper.comment, /PLACEHOLDER PAPER LINK/, "the stand-in paper link carries the PLACEHOLDER marker");
  }
});

test("forced colours get the static story, with the figures written out as text", () => {
  // In forced colours the artwork's dots carry no reliable contrast, so the page takes the
  // same static presentation as reduced motion, and follows the setting when it changes.
  assert.match(page, /const forced = window\.matchMedia\("\(forced-colors: active\)"\);/);
  assert.match(page, /const animated = [^;]*!forced\.matches[^;]*;/, "forced colours turn the animated story off");
  assert.match(page, /forced\.addEventListener\("change", syncPresentation\);/, "a change of the setting re-presents the story");
});
