import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const templateRoot = new URL("../", import.meta.url);

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the OneCVE application shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>OneCVE 本地漏洞检测工作台<\/title>/i);
  assert.match(html, /漏洞检测工作台/);
  assert.match(html, /扫描任务/);
  assert.match(html, /结果统计/);
  assert.doesNotMatch(html, /仅本机访问/);
  assert.match(html, /LLVM Bitcode 生成/);
  assert.doesNotMatch(html, /codex-preview|Codex is working|LLM 编译回退/);
});

test("ships product-specific source without starter artifacts", async () => {
  const [page, layout, css, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(layout, /OneCVE 本地漏洞检测工作台/);
  assert.match(page, /Bitcode 数量/);
  assert.match(page, /源文件数量/);
  assert.match(page, /漏洞 LLM 复核/);
  assert.match(page, /测试 API 连接/);
  assert.match(page, /本地 API 已配置/);
  assert.doesNotMatch(page, /等待 API Key|API Key 未发现/);
  assert.match(page, /已通过/);
  assert.match(page, /未通过/);
  assert.match(page, /复核结果/);
  assert.match(page, /LLM 复核并发线程/);
  assert.match(page, /const SAVED_API_KEY_MASK = "••••••••••••"/);
  assert.match(page, /form\.llm_api_key === SAVED_API_KEY_MASK \? "" : form\.llm_api_key/);
  assert.match(page, /selectedIds=\{selectedFindingIds\}/);
  assert.match(page, /const threads = settings\?\.llm_parallelism \|\| scan\?\.llm_parallelism \|\| 1/);
  assert.match(page, /\["false_positive", "unknown"\]\.includes\(finding\.verdict\)/);
  assert.match(page, /unknown: "未通过", unreviewed: "未复核"/);
  assert.match(page, /unknown: "rejected", unreviewed: "unreviewed"/);
  assert.doesNotMatch(page, />删除所选</);
  assert.doesNotMatch(page, /value: "unknown", label: "复核未知"/);
  assert.doesNotMatch(page, />漏洞信息</);
  assert.match(page, /className="finding-selection-summary">已选择/);
  assert.match(page, /className=\{`llm-review-progress/);
  assert.match(page, /aria-label="LLM 复核进度"/);
  assert.match(page, /共 \{llmReviewProgress\.total\} 条待复核结果/);
  assert.match(page, /当前样本 · 序号/);
  assert.match(page, /estimated_remaining_seconds/);
  assert.match(page, /findings\/llm-review\/progress/);
  assert.match(page, /<th>操作<\/th>/);
  assert.match(page, /document\.documentElement\.style\.overflow = "hidden"/);
  assert.doesNotMatch(page, /llm-result-heading[^\n]*review-pill llm-review/);
  assert.match(page, /<strong className=\{llmReviewClass\(finding\.verdict\)\}>\{verdictName/);
  assert.match(page, /复核状态概览/);
  assert.match(page, /LLM 处理率/);
  assert.match(page, /人工处理率/);
  assert.match(page, /界面统一计为“未通过”/);
  assert.match(page, /className="scan-row-summary"/);
  assert.doesNotMatch(page, /复核未知/);
  assert.doesNotMatch(page, /\["unknown", "复核未知"\]/);
  assert.doesNotMatch(page, /\["ignored", "已忽略"\]/);
  assert.match(page, /<Field label="API Key">/);
  assert.doesNotMatch(page, /API Key 环境变量（高级）/);
  assert.match(page, /className="input-with-hint"/);
  assert.doesNotMatch(page, /历史趋势/);
  assert.match(page, /llm-result-section/);
  assert.match(page, /预计剩余/);
  assert.match(page, /从源码到漏洞检测/);
  assert.match(page, /className="project-table"/);
  assert.match(page, /内存语义建模/);
  assert.doesNotMatch(page, /LLM 复核结论|模型对静态分析证据的辅助判断/);
  assert.match(page, /阶段摘要/);
  assert.match(page, /CWE-401/);
  assert.match(page, /CWE-476/);
  assert.match(page, /conic-gradient/);
  assert.match(page, /ariaLabel="扫描任务筛选"/);
  assert.match(page, /ariaLabel="LLM 复核状态"/);
  assert.match(page, /ariaLabel="人工验证状态"/);
  assert.match(page, /className="finding-filter-menu"/);
  assert.match(page, /stats-project-select/);
  assert.match(page, /aria-haspopup="listbox"/);
  assert.match(page, /className="stats-project-menu"/);
  assert.match(page, /storage-bar segmented/);
  assert.doesNotMatch(page, /onReview\("fixed"\)|标记已修复/);
  assert.doesNotMatch(page, /llm_fallback_enabled|approve-script|自动构建失败后启用 LLM/);
  assert.match(css, /th \{[^}]*font-size:\s*12px/s);
  assert.match(css, /\.finding-head-actions \.button \{[^}]*align-items:\s*center[^}]*justify-content:\s*center[^}]*line-height:\s*1[^}]*white-space:\s*nowrap/s);
  assert.match(css, /\.finding-table-head \{[^}]*font-size:\s*13px/s);
  assert.match(css, /\.finding-selection-summary \{[^}]*grid-column:\s*2 \/ 4/s);
  assert.match(css, /\.llm-progress-track i \{[^}]*transition:\s*width/s);
  assert.doesNotMatch(css, /@keyframes llm-review-progress/);
  assert.match(css, /\.scan-modal-actions \.button \{[^}]*margin-bottom:\s*10px/s);
  assert.match(css, /\.scan-modal-actions \.button\.primary \{[^}]*margin-right:\s*10px/s);
  assert.match(css, /\.scan-parallelism \.field \+ \.field \{[^}]*margin-top:\s*15px/s);
  assert.match(css, /\.drawer \{[^}]*overscroll-behavior:\s*contain/s);
  assert.match(css, /\.llm-result-metrics strong\.rejected \{[^}]*color:\s*#aa433a/s);
  assert.doesNotMatch(css, /\.finding-batch-bar/);
  assert.match(css, /\.finding-check/);
  assert.match(css, /\.review-stat-overview/);
  assert.match(css, /\.review-rate-summary/);
  assert.match(css, /\.scan-row-summary/);
  assert.match(css, /\.input-with-hint > small \{[^}]*position:\s*absolute[^}]*top:\s*50%/s);
  assert.match(css, /\.review-filters/);
  assert.match(css, /\.finding-filter-trigger/);
  assert.match(css, /\.finding-filter-menu/);
  assert.match(css, /grid-template-columns:\s*68px minmax\(0, 1fr\) 25px/);
  assert.match(css, /\.finding-filter-trigger > span, \.finding-filter-trigger > strong \{[^}]*font-size:\s*12px/s);
  assert.match(css, /\.stats-project-select/);
  assert.match(css, /\.stats-project-trigger/);
  assert.match(css, /\.stats-project-menu/);
  assert.match(css, /\.stats-metrics \.metric/);
  assert.match(css, /\.storage-bar\.segmented/);
  assert.match(css, /\.project-table th \{[^}]*text-align:\s*center/s);
  assert.match(css, /\.project-table td:nth-child\(n\+2\):nth-child\(-n\+6\) \{[^}]*text-align:\s*center/s);
  assert.doesNotMatch(css, /writing-mode:\s*vertical-rl/);
  assert.doesNotMatch(page, /label="Bitcode 数量"[^>]*accent/);
  assert.doesNotMatch(page, /label="扫描任务"[^>]*accent/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.deepEqual(await readdir(new URL("app/_sites-preview", templateRoot)), []);
});
