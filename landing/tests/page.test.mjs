import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../src/pages/index.astro", import.meta.url), "utf8");
const artwork = readFileSync(new URL("../src/scripts/particles.js", import.meta.url), "utf8");
const frontmatter = page.split(/^---$/m)[1] ?? "";
const benchScene = page.match(/<div class="copy side" data-copy="bench">[\s\S]*?\n\s*<\/div>\n\s*<\/div>/)?.[0] ?? "";

// The stand-ins the benchmark scene was restored with. They are not results.
const STAND_IN_SCORES = ["60", "80"];
const STAND_IN_PAPER_URL = "[PAPER URL]";

function declaration(name) {
  const lines = frontmatter.split("\n");
  const at = lines.findIndex((line) => line.startsWith(`const ${name} = `));
  assert.notEqual(at, -1, `${name} is declared in the page frontmatter`);
  assert.equal(lines.filter((line) => line.startsWith(`const ${name} = `)).length, 1, `${name} is declared once`);
  let above = "";
  for (let i = at - 1; i >= 0 && lines[i].startsWith("//"); i--) above = `${lines[i]}\n${above}`;
  return { line: lines[at], comment: above };
}

test("the benchmark scene reads every figure from the one BENCH declaration", () => {
  assert.ok(benchScene, "the benchmark scene is on the page");
  const { line } = declaration("BENCH");
  assert.match(line, /scores: \[[^\]]*\]/);
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
  const scores = [...bench.line.match(/scores: \[([^\]]*)\]/)[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
  if (scores.some((score) => STAND_IN_SCORES.includes(score))) {
    assert.match(bench.comment, /PLACEHOLDER BENCHMARK NUMBERS/, "stand-in scores carry the PLACEHOLDER marker");
    assert.match(benchScene, /PLACEHOLDER BENCHMARK NUMBERS/, "the scene markup points at the PLACEHOLDER figures");
  }
  const paper = declaration("PAPER_URL");
  if (paper.line.includes(JSON.stringify(STAND_IN_PAPER_URL))) {
    assert.match(paper.comment, /PLACEHOLDER PAPER LINK/, "the stand-in paper link carries the PLACEHOLDER marker");
  }
});
