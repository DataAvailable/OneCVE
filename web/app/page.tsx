"use client";

import { FormEvent, MouseEvent as ReactMouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  API_BASE,
  Finding,
  LLMReviewProgress,
  MemoryFunctions,
  Project,
  Scan,
  ScanEvent,
  ScanStatistics,
  SourceView,
  StorageStatus,
  api,
  formatBytes,
  formatDate,
  shortId,
} from "./api";

type View = "overview" | "projects" | "scans" | "findings" | "statistics" | "settings";
type Dashboard = {
  metrics: { projects: number; scans: number; findings: number; active_scans: number };
  by_type: Array<{ type: string; count: number }>;
  recent_scans: Scan[];
};
type SystemStatus = {
  tools: Record<string, string | null>;
  paths: Record<string, string>;
  llm: {
    configured: boolean;
    authenticated: boolean;
    local_endpoint: boolean;
    api_key_env: string;
    endpoint: string;
  };
  data_root: string;
  hardware: { logical_cpus: number; memory_bytes: number | null; recommended_scan_parallelism: number; recommended_llm_parallelism: number };
};
type Settings = {
  svf_build_dir: string;
  saber_path: string;
  extapi_path: string;
  clang: string;
  clangxx: string;
  build_timeout: number;
  saber_timeout: number;
  scan_parallelism: number;
  llm_parallelism: number;
  llm_model: string;
  llm_base_url: string;
  llm_chat_path: string;
  llm_api_key_env: string;
  llm_api_key: string;
  llm_api_key_configured: boolean;
  llm_timeout: number;
};
type LLMConnectionTestResult = {
  ok: boolean;
  message: string;
  model: string;
  endpoint: string;
  authenticated: boolean;
};

const emptyDashboard: Dashboard = {
  metrics: { projects: 0, scans: 0, findings: 0, active_scans: 0 },
  by_type: [],
  recent_scans: [],
};

const emptyStatistics: ScanStatistics = {
  summary: { scans: 0, completed_scans: 0, findings: 0, avg_duration_seconds: 0, bitcode_count: 0, source_file_count: 0 },
  by_type: [],
  review_status: { llm: {}, manual: {} },
  recent_scans: [],
};

const vulnerabilityNames: Record<string, string> = {
  memory_leak: "内存泄漏",
  double_free: "重复释放",
  use_after_free: "释放后引用",
  file_leak: "文件未关闭",
  null_deref: "空指针解引用",
};

const vulnerabilityCwes: Record<string, string> = {
  memory_leak: "CWE-401",
  double_free: "CWE-415",
  use_after_free: "CWE-416",
  file_leak: "CWE-775",
  null_deref: "CWE-476",
};

const vulnerabilityColors: Record<string, string> = {
  memory_leak: "#3f7d62",
  double_free: "#c86c55",
  use_after_free: "#d49a3a",
  file_leak: "#5d86a7",
  null_deref: "#8067a9",
};

const stageNames: Record<string, string> = {
  queued: "等待执行",
  preparing: "准备项目",
  building: "生成 Bitcode",
  analyzing: "漏洞扫描",
  parsing: "解析结果",
  verifying: "LLM 复核",
  cancelling: "正在停止",
  cancelled: "已取消",
  completed: "已完成",
  failed: "失败",
  interrupted: "异常中断",
  cleanup: "产物清理",
};

const checkerInfo = [
  { id: "leak", label: "内存泄漏", code: "LEAK" },
  { id: "dfree", label: "重复释放", code: "DFREE" },
  { id: "uaf", label: "释放后引用", code: "UAF" },
  { id: "fileck", label: "文件未关闭", code: "FILE" },
  { id: "npd", label: "空指针解引用", code: "NPD" },
];

const SAVED_API_KEY_MASK = "••••••••••••";

export default function Home() {
  const [view, setView] = useState<View>("overview");
  const [dashboard, setDashboard] = useState<Dashboard>(emptyDashboard);
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [storage, setStorage] = useState<StorageStatus | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [statistics, setStatistics] = useState<ScanStatistics>(emptyStatistics);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [highlightedFindingId, setHighlightedFindingId] = useState("");
  const [findingFilter, setFindingFilter] = useState("all");
  const [llmReviewFilter, setLlmReviewFilter] = useState("all");
  const [manualReviewFilter, setManualReviewFilter] = useState("all");
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [llmReviewProgress, setLlmReviewProgress] = useState<LLMReviewProgress | null>(null);
  const [projectModal, setProjectModal] = useState(false);
  const [scanProject, setScanProject] = useState<Project | null>(null);
  const [memoryProject, setMemoryProject] = useState<Project | null>(null);
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const [notice, setNotice] = useState<string>("");

  const refresh = useCallback(async () => {
    try {
      const [dashboardData, projectData, scanData, systemData, statisticsData, settingsData] = await Promise.all([
        api<Dashboard>("/api/dashboard"),
        api<Project[]>("/api/projects"),
        api<Scan[]>("/api/scans"),
        api<SystemStatus>("/api/system"),
        api<ScanStatistics>("/api/statistics"),
        api<Settings>("/api/settings"),
      ]);
      setDashboard(dashboardData);
      setProjects(projectData);
      setScans(scanData);
      setSystem(systemData);
      setStatistics(statisticsData);
      setSettings(settingsData);
      setConnected(true);
      if (!selectedScanId && scanData[0]) setSelectedScanId(scanData[0].id);
    } catch (error) {
      setConnected(false);
      setNotice(error instanceof Error ? error.message : "无法连接本地 API");
    }
  }, [selectedScanId]);

  const refreshSelectedScan = useCallback(async () => {
    if (!selectedScanId) {
      setSelectedScan(null);
      setFindings([]);
      setEvents([]);
      return;
    }
    try {
      const [scan, scanEvents, scanFindings] = await Promise.all([
        api<Scan>(`/api/scans/${selectedScanId}`),
        api<ScanEvent[]>(`/api/scans/${selectedScanId}/events`),
        api<Finding[]>(`/api/scans/${selectedScanId}/findings`),
      ]);
      setSelectedScan(scan);
      setEvents(scanEvents);
      setFindings(scanFindings);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "无法读取扫描详情");
    }
  }, [selectedScanId]);

  const refreshStorage = useCallback(async () => {
    try {
      setStorage(await api<StorageStatus>("/api/storage"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "无法读取磁盘占用");
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refresh();
      void refreshStorage();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh, refreshStorage]);

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshSelectedScan(), 0);
    return () => window.clearTimeout(timer);
  }, [refreshSelectedScan]);

  useEffect(() => {
    const hasActive = scans.some((scan) => ["queued", "running", "cancelling"].includes(scan.status));
    if (!hasActive) return;
    const timer = window.setInterval(() => {
      void refresh();
      void refreshSelectedScan();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [scans, refresh, refreshSelectedScan]);

  useEffect(() => {
    const timer = window.setInterval(() => void refreshStorage(), 30000);
    return () => window.clearInterval(timer);
  }, [refreshStorage]);

  useEffect(() => setSelectedFindingIds([]), [selectedScanId]);

  useEffect(() => {
    setSelectedFindingIds((current) => current.filter((id) => findings.some((finding) => finding.id === id)));
  }, [findings]);

  const filteredFindings = useMemo(
    () => findings.filter((finding) => {
      const matchesType = findingFilter === "all" || finding.vulnerability_type === findingFilter;
      const matchesLlm = llmReviewFilter === "all" ||
        (llmReviewFilter === "passed" && finding.verdict === "true_positive") ||
        (llmReviewFilter === "rejected" && ["false_positive", "unknown"].includes(finding.verdict)) ||
        (llmReviewFilter === "unreviewed" && finding.verdict === "unreviewed");
      const matchesManual = manualReviewFilter === "all" ||
        (manualReviewFilter === "verified" ? finding.review_status === "confirmed" : finding.review_status === "pending");
      return matchesType && matchesLlm && matchesManual;
    }),
    [findings, findingFilter, llmReviewFilter, manualReviewFilter],
  );

  async function runAction(action: () => Promise<void>, refreshDetails = true) {
    setBusy(true);
    setNotice("");
    try {
      await action();
      await refresh();
      await refreshStorage();
      if (refreshDetails) await refreshSelectedScan();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "操作失败");
    } finally {
      setBusy(false);
    }
  }

  function cleanProject(project: Project) {
    if (!window.confirm(`清理“${project.name}”所有扫描的 Bitcode 和临时构建目录？漏洞结果与报告会保留。`)) return;
    void runAction(async () => {
      const result = await api<{ freed_bytes: number; cleaned_scans: number }>(
        `/api/projects/${project.id}/artifacts/cleanup`,
        { method: "POST" },
      );
      setNotice(`已清理 ${result.cleaned_scans} 个任务的构建产物，释放 ${formatBytes(result.freed_bytes)}`);
    });
  }

  function deleteProject(project: Project) {
    const sourceNote = project.source_kind === "local" ? "外部源码目录不会被删除。" : "OneCVE 管理的源码副本也会删除。";
    if (!window.confirm(`确定删除项目“${project.name}”及其全部扫描、日志和漏洞结果？\n${sourceNote}`)) return;
    void runAction(async () => {
      const result = await api<{ freed_bytes: number }>(`/api/projects/${project.id}`, { method: "DELETE" });
      if (selectedScan?.project_id === project.id) {
        setSelectedScanId("");
        setSelectedScan(null);
        setFindings([]);
        setEvents([]);
      }
      setNotice(`项目已删除，释放 ${formatBytes(result.freed_bytes)}`);
    }, false);
  }

  function cancelScanIds(scanIds: string[]) {
    const activeIds = scanIds.filter((id) => scans.some((scan) => scan.id === id && ["queued", "running", "cancelling"].includes(scan.status)));
    if (!activeIds.length) {
      setNotice("所选任务中没有正在运行或等待的任务");
      return;
    }
    if (!window.confirm(`确定终止选中的 ${activeIds.length} 个扫描任务？`)) return;
    void runAction(async () => {
      await api("/api/scans/bulk-cancel", { method: "POST", body: JSON.stringify({ scan_ids: activeIds }) });
      setNotice(`已向 ${activeIds.length} 个任务发送终止请求`);
    });
  }

  function deleteScanIds(scanIds: string[]) {
    if (!scanIds.length || !window.confirm(`确定删除选中的 ${scanIds.length} 个扫描任务及其日志、报告和漏洞结果？`)) return;
    void runAction(async () => {
      const result = await api<{ deleted_count: number; freed_bytes: number }>("/api/scans/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ scan_ids: scanIds }),
      });
      if (scanIds.includes(selectedScanId)) {
        setSelectedScanId("");
        setSelectedScan(null);
        setFindings([]);
        setEvents([]);
      }
      setNotice(`已删除 ${result.deleted_count} 个任务，释放 ${formatBytes(result.freed_bytes)}`);
    }, false);
  }

  function clearFindings(scanId: string) {
    const scan = scans.find((item) => item.id === scanId);
    if (!scan || !window.confirm(`确定清空“${scan.project_name}”本次扫描的全部漏洞结果和报告？\n扫描任务、日志与构建产物会保留。`)) return;
    void runAction(async () => {
      const result = await api<{ cleared_count: number; freed_bytes: number }>(
        `/api/scans/${scanId}/findings`,
        { method: "DELETE" },
      );
      setSelectedFinding(null);
      setHighlightedFindingId("");
      setNotice(`已清空 ${result.cleared_count} 条漏洞结果，释放 ${formatBytes(result.freed_bytes)}`);
    });
  }

  function deleteFindings(scanId: string, findingIds: string[]) {
    if (!findingIds.length || !window.confirm(`确定删除选中的 ${findingIds.length} 条漏洞结果？\n原始 Saber 报告和其它结果会保留。`)) return;
    void runAction(async () => {
      const result = await api<{ deleted_count: number }>(
        `/api/scans/${scanId}/findings/bulk-delete`,
        { method: "POST", body: JSON.stringify({ finding_ids: findingIds }) },
      );
      setSelectedFinding(null);
      setHighlightedFindingId("");
      setNotice(`已删除 ${result.deleted_count} 条漏洞结果`);
    });
  }

  function reviewFindingsWithLlm(scanId: string, findingIds: string[]) {
    const scan = scans.find((item) => item.id === scanId);
    const threads = settings?.llm_parallelism || scan?.llm_parallelism || 1;
    if (!findingIds.length || !window.confirm(`使用 ${threads} 个并发线程复核选中的 ${findingIds.length} 条结果？`)) return;
    const firstFinding = findings.find((finding) => finding.id === findingIds[0]);
    setLlmReviewProgress({
      scan_id: scanId,
      active: true,
      total: findingIds.length,
      completed: 0,
      percent: 0,
      current_index: 1,
      current_finding_id: findingIds[0] || "",
      current_sample: firstFinding
        ? `${firstFinding.file}:${firstFinding.line}:${firstFinding.column}`
        : "准备复核样本",
      elapsed_seconds: 0,
      estimated_remaining_seconds: null,
      error: null,
    });
    void (async () => {
      const pollProgress = async () => {
        try {
          const progress = await api<LLMReviewProgress>(`/api/scans/${scanId}/findings/llm-review/progress`);
          if (progress.total > 0) setLlmReviewProgress(progress);
        } catch {
          // The POST may not have initialized its progress record yet.
        }
      };
      const timer = window.setInterval(() => void pollProgress(), 500);
      try {
        await runAction(async () => {
          const result = await api<{ reviewed_count: number; passed: number; rejected: number; unknown: number; api_errors: number }>(
            `/api/scans/${scanId}/findings/llm-review`,
            { method: "POST", body: JSON.stringify({ finding_ids: findingIds }) },
          );
          setNotice(`LLM 复核完成：已通过 ${result.passed}，未通过 ${result.rejected + result.unknown}${result.api_errors ? `，其中 API 错误 ${result.api_errors}` : ""}`);
        });
      } finally {
        window.clearInterval(timer);
        await pollProgress();
        window.setTimeout(
          () => setLlmReviewProgress((current) =>
            current?.scan_id === scanId && !current.active ? null : current
          ),
          1400,
        );
      }
    })();
  }

  function reviewFinding(finding: Finding, status: string) {
    setSelectedFinding(null);
    void runAction(async () => {
      await api<Finding>(`/api/findings/${finding.id}/review`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      setHighlightedFindingId(finding.id);
      setNotice(`已将结果标记为“${manualReviewName(status)}”`);
    });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><span>O</span></div>
          <div><strong>OneCVE</strong><small>漏洞检测工作台</small></div>
        </div>
        <nav aria-label="主导航">
          <NavItem active={view === "overview"} onClick={() => setView("overview")} glyph="⌂" label="总览" />
          <NavItem active={view === "projects"} onClick={() => setView("projects")} glyph="▦" label="项目" count={projects.length} />
          <NavItem active={view === "scans"} onClick={() => setView("scans")} glyph="search" label="扫描任务" count={dashboard.metrics.active_scans || undefined} />
          <NavItem active={view === "findings"} onClick={() => setView("findings")} glyph="bug" label="漏洞结果" count={dashboard.metrics.findings || undefined} />
          <NavItem active={view === "statistics"} onClick={() => setView("statistics")} glyph="▥" label="结果统计" />
        </nav>
        <div className="sidebar-bottom">
          <NavItem active={view === "settings"} onClick={() => setView("settings")} glyph="⚙" label="本地设置" />
          <div className="local-mode"><i className={connected ? "online" : "offline"} /><span>{connected ? "本地服务正常" : "本地服务离线"}</span></div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">LOCAL STATIC ANALYSIS</p>
            <h1>{viewTitle(view)}</h1>
          </div>
          {view !== "projects" && <div className="top-actions"><button className="button primary" onClick={() => setProjectModal(true)}>＋ 导入项目</button></div>}
        </header>

        {notice && <div className="notice" role="alert"><span>{notice}</span><button onClick={() => setNotice("")}>×</button></div>}

        {view === "overview" && (
          <Overview dashboard={dashboard} scans={scans} system={system} storage={storage} onNew={() => setProjectModal(true)} onNavigate={setView} onOpenScan={(id) => { setSelectedScanId(id); setView("scans"); }} />
        )}
        {view === "projects" && (
          <Projects projects={projects} storage={storage} busy={busy} onNew={() => setProjectModal(true)} onScan={setScanProject} onMemory={setMemoryProject} onClean={cleanProject} onDelete={deleteProject} />
        )}
        {view === "scans" && (
          <Scans scans={scans} selected={selectedScan} events={events} busy={busy} onSelect={setSelectedScanId} onCancel={(id) => cancelScanIds([id])} onDelete={(id) => deleteScanIds([id])} onBulkCancel={cancelScanIds} onBulkDelete={deleteScanIds} />
        )}
        {view === "findings" && (
          <Findings scans={scans} selectedScanId={selectedScanId} onScanChange={setSelectedScanId} findings={filteredFindings} totalFindings={findings.length} hasFindings={findings.length > 0} highlightedFindingId={highlightedFindingId} busy={busy} filter={findingFilter} onFilter={setFindingFilter} llmFilter={llmReviewFilter} onLlmFilter={setLlmReviewFilter} manualFilter={manualReviewFilter} onManualFilter={setManualReviewFilter} selectedIds={selectedFindingIds} onSelectedIdsChange={setSelectedFindingIds} llmReviewProgress={llmReviewProgress} onSelect={setSelectedFinding} onClear={clearFindings} onDelete={deleteFindings} onLlmReview={reviewFindingsWithLlm} />
        )}
        {view === "statistics" && <StatisticsPanel statistics={statistics} projects={projects} onReload={setStatistics} />}
        {view === "settings" && settings && (
          <SettingsPanel settings={settings} system={system} onSave={(value) => runAction(async () => { const saved = await api<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(value) }); setSettings(saved); setNotice("设置已保存"); })} />
        )}
      </main>

      {projectModal && <ProjectModal busy={busy} onClose={() => setProjectModal(false)} onSubmit={(payload) => runAction(async () => { await createProject(payload); setProjectModal(false); setView("projects"); })} />}
      {scanProject && <ScanModal project={scanProject} busy={busy} defaultParallelism={settings?.scan_parallelism || system?.hardware.recommended_scan_parallelism || 1} defaultLlmParallelism={settings?.llm_parallelism || system?.hardware.recommended_llm_parallelism || 1} onClose={() => setScanProject(null)} onSubmit={(payload) => runAction(async () => { const scan = await api<Scan>(`/api/projects/${scanProject.id}/scans`, { method: "POST", body: JSON.stringify(payload) }); setSelectedScanId(scan.id); setScanProject(null); setView("scans"); })} />}
      {memoryProject && <MemoryFunctionsModal project={memoryProject} busy={busy} onClose={() => setMemoryProject(null)} onNotice={setNotice} />}
      {selectedFinding && <FindingDrawer finding={selectedFinding} busy={busy} onClose={() => setSelectedFinding(null)} onReview={(status) => reviewFinding(selectedFinding, status)} />}
    </div>
  );
}

function NavItem({ active, onClick, glyph, label, count }: { active: boolean; onClick: () => void; glyph: string; label: string; count?: number }) {
  const customIcon = glyph === "search" || glyph === "bug";
  return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}><span className={`nav-glyph ${customIcon ? `icon-${glyph}` : ""}`} aria-hidden>{customIcon ? "" : glyph}</span><span>{label}</span>{count ? <b>{count}</b> : null}</button>;
}

function Overview({ dashboard, scans, system, storage, onNew, onNavigate, onOpenScan }: { dashboard: Dashboard; scans: Scan[]; system: SystemStatus | null; storage: StorageStatus | null; onNew: () => void; onNavigate: (view: View) => void; onOpenScan: (id: string) => void }) {
  const latest = scans[0];
  return <div className="content-stack">
    <section className="hero-panel">
      <div className="hero-copy"><span className="section-tag">ONE-CLICK PIPELINE</span><h2>从源码到漏洞检测<br />只需一键</h2><p>自动识别构建系统，生成 LLVM Bitcode，并运行内存泄漏、重复释放、释放后引用、文件未关闭与空指针解引用五类检测。漏洞结果可选用 LLM 进行语义复核。</p><div className="hero-actions"><button className="button light" onClick={onNew}>开始新扫描</button>{latest && <button className="button ghost-light" onClick={() => onOpenScan(latest.id)}>查看最近任务 →</button>}</div></div>
      <div className="pipeline-card"><div className="pipeline-title"><span>分析流水线</span><i>LOCAL</i></div>{["源码与构建识别", "LLVM Bitcode 生成", "内存语义建模", "漏洞扫描", "证据解析与 LLM 复核"].map((label, index) => <div className="pipeline-step" key={label}><b>{String(index + 1).padStart(2, "0")}</b><span>{label}</span><em className={index < 4 ? "ready" : "conditional"}>{index < 4 ? "自动" : "可选"}</em></div>)}</div>
    </section>
    <section className="metric-grid">
      <Metric label="本地项目" value={dashboard.metrics.projects} note="已纳入工作台" onClick={() => onNavigate("projects")} />
      <Metric label="扫描任务" value={dashboard.metrics.scans} note={`${dashboard.metrics.active_scans} 个正在运行`} onClick={() => onNavigate("scans")} />
      <Metric label="漏洞结果" value={dashboard.metrics.findings} note="去重后的检测结果" onClick={() => onNavigate("findings")} />
      <div className="metric"><span>OneCVE 存储</span><strong className="metric-size">{formatBytes(storage?.onecve.data_bytes || 0)}</strong><small>可清理 {formatBytes(storage?.onecve.reclaimable_bytes || 0)}</small></div>
    </section>
    <StoragePanel storage={storage} />
    <section className="two-column">
      <div className="panel"><PanelHeader title="最近扫描" subtitle="任务状态与执行进度" />{dashboard.recent_scans.length ? <div className="scan-list">{dashboard.recent_scans.slice(0, 5).map((scan) => <button className="scan-row" key={scan.id} onClick={() => onOpenScan(scan.id)}><StatusDot status={scan.status} /><div><strong>{scan.project_name}</strong><small>{shortId(scan.id)} · {formatDate(scan.created_at)}</small></div><div className="scan-row-summary"><span><b>{scan.bitcode_count}</b> Bitcode</span><span><b>{scan.finding_count}</b> 条结果</span></div><div className="row-progress"><span style={{ width: `${scan.progress}%` }} /></div><b>{scan.progress}%</b></button>)}</div> : <EmptyState title="还没有扫描任务" text="导入一个 C/C++ 项目即可开始。" action="导入项目" onAction={onNew} />}</div>
      <div className="panel readiness"><PanelHeader title="运行环境" subtitle="本机工具链就绪情况" />{system ? <div className="tool-grid">{["clang", "cmake", "bear", "bash"].map((tool) => <div key={tool}><i className={system.tools[tool] ? "ok" : "missing"}>{system.tools[tool] ? "✓" : "!"}</i><span>{tool}</span><small>{system.tools[tool] ? "已发现" : "未配置"}</small></div>)}</div> : <div className="loading-line" /> }<div className={`llm-band ${system?.llm.configured ? "configured" : ""}`}><span>漏洞 LLM 复核</span><strong>{system?.llm.configured ? llmConfigurationLabel(system.llm) : "等待配置"}</strong></div></div>
    </section>
  </div>;
}

function StoragePanel({ storage }: { storage: StorageStatus | null }) {
  if (!storage) return <section className="panel storage-panel"><div className="loading-line" /></section>;
  const usedPercent = storage.filesystem.total_bytes ? Math.round(storage.filesystem.used_bytes / storage.filesystem.total_bytes * 100) : 0;
  const scanOther = Math.max(0, storage.onecve.scans_bytes - storage.onecve.build_bytes - storage.onecve.reports_bytes);
  const onecveOther = Math.max(0, storage.onecve.data_bytes - storage.onecve.projects_bytes - storage.onecve.scans_bytes);
  const externalUsed = Math.max(0, storage.filesystem.used_bytes - storage.onecve.data_bytes);
  const segments = [
    { key: "projects", label: "项目源码副本", bytes: storage.onecve.projects_bytes, color: "#4f8f70" },
    { key: "scans", label: "扫描其它数据", bytes: scanOther, color: "#6689a8" },
    { key: "build", label: "构建产物", bytes: storage.onecve.build_bytes, color: "#c18a43" },
    { key: "reports", label: "漏洞报告", bytes: storage.onecve.reports_bytes, color: "#b96b61" },
    { key: "other", label: "OneCVE 其它数据", bytes: onecveOther, color: "#81759c" },
    { key: "external", label: "系统其它占用", bytes: externalUsed, color: "#aab4ae" },
    { key: "free", label: "磁盘可用", bytes: storage.filesystem.free_bytes, color: "#e6ece8" },
  ];
  const segmentWidth = (bytes: number) => storage.filesystem.total_bytes ? Math.max(bytes > 0 ? 0.35 : 0, bytes / storage.filesystem.total_bytes * 100) : 0;
  return <section className="panel storage-panel"><div className="storage-heading"><div><h3>磁盘占用</h3><p>OneCVE 数据目录与所在磁盘空间</p></div><strong>{usedPercent}% 已使用</strong></div><div className="storage-bar segmented" aria-label="磁盘空间分类占用">{segments.map((segment) => <i key={segment.key} title={`${segment.label}：${formatBytes(segment.bytes)}`} style={{ width: `${segmentWidth(segment.bytes)}%`, background: segment.color }} />)}</div><div className="storage-breakdown"><div className="storage-projects"><span>项目源码副本</span><b>{formatBytes(storage.onecve.projects_bytes)}</b></div><div className="storage-scans"><span>扫描其它数据</span><b>{formatBytes(scanOther)}</b></div><div className="storage-build"><span>构建产物</span><b>{formatBytes(storage.onecve.build_bytes)}</b></div><div className="storage-reports"><span>漏洞报告</span><b>{formatBytes(storage.onecve.reports_bytes)}</b></div><div className="storage-total"><span>OneCVE 合计</span><b>{formatBytes(storage.onecve.data_bytes)}</b></div><div className="storage-free"><span>磁盘可用</span><b>{formatBytes(storage.filesystem.free_bytes)}</b></div></div></section>;
}

function Metric({ label, value, note, accent = false, onClick }: { label: string; value: number; note: string; accent?: boolean; onClick?: () => void }) {
  const content = <><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{note}{onClick && " · 点击查看"}</small></>;
  return onClick ? <button type="button" className={`metric metric-link ${accent ? "accent" : ""}`} onClick={onClick}>{content}</button> : <div className={`metric ${accent ? "accent" : ""}`}>{content}</div>;
}
function PanelHeader({ title, subtitle }: { title: string; subtitle: string }) { return <div className="panel-header"><div><h3>{title}</h3><p>{subtitle}</p></div></div>; }
function StatusDot({ status }: { status: string }) { return <i className={`status-dot ${status}`} aria-label={status} />; }

function Projects({ projects, storage, busy, onNew, onScan, onMemory, onClean, onDelete }: { projects: Project[]; storage: StorageStatus | null; busy: boolean; onNew: () => void; onScan: (project: Project) => void; onMemory: (project: Project) => void; onClean: (project: Project) => void; onDelete: (project: Project) => void }) {
  const usage = new Map((storage?.projects || []).map((item) => [item.project_id, item]));
  return <section className="panel full"><div className="section-head"><div><h2>项目资产</h2><p>本地路径、源码包与公开 Git 仓库统一管理。</p></div><button className="button primary" onClick={onNew}>＋ 导入项目</button></div>{projects.length ? <div className="table-wrap"><table className="project-table"><thead><tr><th>项目</th><th>来源</th><th>构建系统</th><th>源文件</th><th>扫描 / 结果</th><th>占用</th><th>操作</th></tr></thead><tbody>{projects.map((project) => { const projectUsage = usage.get(project.id); return <tr key={project.id}><td><div className="project-name"><span>{project.name.slice(0, 2).toUpperCase()}</span><div><strong>{project.name}</strong><small title={project.source_path}>{project.source_path}</small></div></div></td><td><span className="soft-badge">{sourceKind(project.source_kind)}</span></td><td><code>{project.build_system}</code></td><td>{project.source_files}</td><td>{project.scan_count} / {project.finding_count}</td><td><span className="storage-cell">{formatBytes(projectUsage?.total_bytes || 0)}</span><small className="reclaimable">可清理 {formatBytes(projectUsage?.build_bytes || 0)}</small></td><td><div className="row-actions"><button disabled={busy} className="button compact" onClick={() => onScan(project)}>扫描</button><button disabled={busy} className="button compact secondary" onClick={() => onMemory(project)}>内存函数</button><button disabled={busy || !projectUsage?.build_bytes} className="button compact secondary" onClick={() => onClean(project)}>清理产物</button><button disabled={busy} className="button compact danger-text" onClick={() => onDelete(project)}>删除</button></div></td></tr>; })}</tbody></table></div> : <EmptyState title="导入第一个项目" text="可选择本地源码目录、上传压缩包或填写公开 Git 地址。" action="导入项目" onAction={onNew} />}</section>;
}

function Scans({ scans, selected, events, busy, onSelect, onCancel, onDelete, onBulkCancel, onBulkDelete }: { scans: Scan[]; selected: Scan | null; events: ScanEvent[]; busy: boolean; onSelect: (id: string) => void; onCancel: (id: string) => void; onDelete: (id: string) => void; onBulkCancel: (ids: string[]) => void; onBulkDelete: (ids: string[]) => void }) {
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [showDetailedLogs, setShowDetailedLogs] = useState(false);
  useEffect(() => { const timer = window.setTimeout(() => setSelectedIds((current) => current.filter((id) => scans.some((scan) => scan.id === id))), 0); return () => window.clearTimeout(timer); }, [scans]);
  useEffect(() => { const timer = window.setTimeout(() => setShowDetailedLogs(false), 0); return () => window.clearTimeout(timer); }, [selected?.id]);
  const active = (scan: Scan) => ["queued", "running", "cancelling"].includes(scan.status);
  const selectedScans = scans.filter((scan) => selectedIds.includes(scan.id));
  const hasActiveSelection = selectedScans.some(active);
  const visibleEvents = useMemo(() => showDetailedLogs ? events : summarizeScanEvents(events), [events, showDetailedLogs]);
  const toggle = (id: string) => setSelectedIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  const toggleAll = () => setSelectedIds(selectedIds.length === scans.length ? [] : scans.map((scan) => scan.id));
  return <div className="scan-layout"><section className="panel scan-index"><div className="section-head compact-head"><div><h2>扫描任务</h2><p>{scans.length} 条本地记录</p></div>{scans.length > 0 && <label className="select-all"><input type="checkbox" checked={selectedIds.length === scans.length} onChange={toggleAll} />全选</label>}</div>{selectedIds.length > 0 && <div className="bulk-bar"><span>已选 {selectedIds.length} 项</span><button disabled={busy || !hasActiveSelection} onClick={() => onBulkCancel(selectedIds)}>终止</button><button disabled={busy || hasActiveSelection} title={hasActiveSelection ? "请先终止运行中的任务" : ""} onClick={() => onBulkDelete(selectedIds)}>删除</button></div>}{scans.length ? scans.map((scan) => <div className="scan-card-wrap" key={scan.id}><label className="scan-check" title="选择任务"><input type="checkbox" checked={selectedIds.includes(scan.id)} onChange={() => toggle(scan.id)} /></label><button className={`scan-card ${selected?.id === scan.id ? "selected" : ""}`} onClick={() => onSelect(scan.id)}><div className="scan-card-top"><StatusDot status={scan.status} /><strong>{scan.project_name}</strong><span>{formatDate(scan.created_at)}</span></div><p>{stageNames[scan.stage] || scan.stage}</p><div className="progress"><i style={{ width: `${scan.progress}%` }} /></div><div className="scan-card-foot"><code>{shortId(scan.id)}</code><b>{formatProgress(scan.progress)} · {scan.finding_count} 结果</b></div></button></div>) : <EmptyState title="暂无扫描" text="请先从项目页启动任务。" />}</section>
    <section className="panel scan-detail">{selected ? <><div className="scan-detail-head"><div><span className={`status-pill ${selected.status}`}>{statusName(selected.status)}</span><h2>{selected.project_name}</h2><p>任务 {shortId(selected.id)} · {selected.checkers.map((item) => item.toUpperCase()).join(" / ")}</p></div><div className="detail-actions">{["queued", "running"].includes(selected.status) && <button disabled={busy} className="button danger" onClick={() => onCancel(selected.id)}>终止任务</button>}{selected.status === "cancelling" && <button disabled className="button">正在终止…</button>}{!active(selected) && <button disabled={busy} className="button danger-text" onClick={() => onDelete(selected.id)}>删除任务</button>}</div></div><div className="stage-banner"><div><span>{stageNames[selected.stage] || selected.stage}</span><div className="stage-progress-meta"><em>{remainingTimeLabel(selected)}</em><strong>{formatProgress(selected.progress)}</strong></div></div><div className="progress large"><i style={{ width: `${selected.progress}%` }} /></div><small>{selected.bitcode_count} 个 Bitcode · {selected.finding_count} 条结果 · {selected.scan_parallelism} 个 Saber 进程{selected.verify_enabled ? ` · ${selected.llm_parallelism} 个 LLM 线程` : ""} · {selected.build_strategy || "等待构建"}</small></div>
      {(selected.custom_alloc.length > 0 || selected.custom_free.length > 0) && <div className="scan-memory-summary"><strong>项目内存函数配置</strong><span>{selected.custom_alloc.length} 个分配函数 · {selected.custom_free.length} 个释放函数</span></div>}
      {selected.error && <div className="error-block"><strong>任务诊断</strong><pre>{selected.error}</pre></div>}
      <div className="timeline-head"><div><h3>运行日志</h3><span>{showDetailedLogs ? `完整日志 · ${events.length} 条` : `阶段摘要 · ${visibleEvents.length} 条`}</span></div>{events.length > 0 && <button className="log-detail-toggle" onClick={() => setShowDetailedLogs((value) => !value)}>{showDetailedLogs ? "收起详情" : "详情"}</button>}</div><div className={`event-log ${showDetailedLogs ? "detailed" : "summary"}`}>{visibleEvents.length ? visibleEvents.map((event) => <div className={`event ${event.level}`} key={`${showDetailedLogs ? "detail" : "summary"}-${event.id}`}><time>{new Date(event.created_at).toLocaleTimeString("zh-CN", { hour12: false })}</time><span>{stageNames[event.stage] || event.stage}</span><p>{event.message}</p></div>) : <p className="muted">等待任务日志……</p>}</div></> : <EmptyState title="选择一个扫描任务" text="这里将显示构建阶段、实时日志和检测结果。" />}</section></div>;
}

function FindingFilterSelect({ label, ariaLabel, value, options, onChange, className = "" }: { label: string; ariaLabel: string; value: string; options: Array<{ value: string; label: string; description?: string }>; onChange: (value: string) => void; className?: string }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const selected = options.find((option) => option.value === value) || options[0];

  useEffect(() => {
    function closeOnOutsideClick(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  function choose(nextValue: string) {
    setOpen(false);
    if (nextValue !== value) onChange(nextValue);
  }

  return <div ref={rootRef} className={`finding-filter-select ${className} ${open ? "open" : ""}`}>
    <button type="button" className="finding-filter-trigger" aria-label={ariaLabel} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen((current) => !current)}>
      <span>{label}</span><strong title={selected?.label}>{selected?.label}</strong><i aria-hidden />
    </button>
    {open && <div className="finding-filter-menu" role="listbox" aria-label={`${label}选项`}>
      {options.map((option) => <button type="button" role="option" aria-selected={option.value === value} className={option.value === value ? "selected" : ""} key={option.value} onClick={() => choose(option.value)}><span><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span><i aria-hidden>✓</i></button>)}
    </div>}
  </div>;
}

function Findings({ scans, selectedScanId, onScanChange, findings, totalFindings, hasFindings, highlightedFindingId, busy, filter, onFilter, llmFilter, onLlmFilter, manualFilter, onManualFilter, selectedIds, onSelectedIdsChange, llmReviewProgress, onSelect, onClear, onDelete, onLlmReview }: { scans: Scan[]; selectedScanId: string; onScanChange: (id: string) => void; findings: Finding[]; totalFindings: number; hasFindings: boolean; highlightedFindingId: string; busy: boolean; filter: string; onFilter: (value: string) => void; llmFilter: string; onLlmFilter: (value: string) => void; manualFilter: string; onManualFilter: (value: string) => void; selectedIds: string[]; onSelectedIdsChange: (ids: string[]) => void; llmReviewProgress: LLMReviewProgress | null; onSelect: (finding: Finding) => void; onClear: (scanId: string) => void; onDelete: (scanId: string, findingIds: string[]) => void; onLlmReview: (scanId: string, findingIds: string[]) => void }) {
  const scanOptions = [{ value: "", label: "选择扫描任务", description: "选择需要查看的检测结果" }, ...scans.map((scan) => ({ value: scan.id, label: `${scan.project_name} · ${shortId(scan.id)}`, description: statusName(scan.status) }))];
  const llmOptions = [{ value: "all", label: "全部", description: "显示所有 LLM 复核状态" }, { value: "passed", label: "已通过", description: "LLM 判断漏洞确实存在" }, { value: "rejected", label: "未通过", description: "LLM 判断该结果不是漏洞" }, { value: "unreviewed", label: "未复核", description: "尚未调用 LLM 复核" }];
  const manualOptions = [{ value: "all", label: "全部", description: "显示所有人工验证状态" }, { value: "verified", label: "已验证", description: "已经人工确认的漏洞" }, { value: "unverified", label: "未验证", description: "尚未进行人工确认" }];
  const allSelected = findings.length > 0 && findings.every((finding) => selectedIds.includes(finding.id));
  function toggleAll() { onSelectedIdsChange(allSelected ? [] : findings.map((finding) => finding.id)); }
  function toggleFinding(id: string) { onSelectedIdsChange(selectedIds.includes(id) ? selectedIds.filter((item) => item !== id) : [...selectedIds, id]); }
  return <section className="panel full"><div className="section-head"><div><h2>漏洞结果</h2><p>按检测类型、源码位置和复核状态查看证据。</p></div><div className="finding-head-actions"><FindingFilterSelect label="扫描任务" ariaLabel="扫描任务筛选" value={selectedScanId} options={scanOptions} onChange={onScanChange} className="scan-task-filter" /><button className="button secondary" disabled={busy || !selectedIds.length} onClick={() => onLlmReview(selectedScanId, selectedIds)}>LLM 复核</button><button title={selectedIds.length ? `删除已选中的 ${selectedIds.length} 条结果` : "清空当前扫描的全部结果"} disabled={busy || !selectedScanId || !hasFindings} className="button danger-text" onClick={() => selectedIds.length ? onDelete(selectedScanId, selectedIds) : onClear(selectedScanId)}>清空结果</button></div></div>{llmReviewProgress && <div className={`llm-review-progress ${llmReviewProgress.error ? "failed" : llmReviewProgress.active ? "active" : "complete"}`} role="progressbar" aria-label="LLM 复核进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(llmReviewProgress.percent)}><div className="llm-progress-heading"><div><strong>{llmReviewProgress.error ? "LLM 复核中断" : llmReviewProgress.active ? "正在进行 LLM 复核" : "LLM 复核完成"}</strong><span>共 {llmReviewProgress.total} 条待复核结果</span></div><b>{formatProgress(llmReviewProgress.percent)}</b></div><div className="llm-progress-track"><i style={{ width: `${Math.max(0, Math.min(100, llmReviewProgress.percent))}%` }} /></div><div className="llm-progress-details"><span><small>完成进度</small><strong>{llmReviewProgress.completed} / {llmReviewProgress.total}</strong></span><span className="current-sample" title={llmReviewProgress.current_sample}><small>当前样本 · 序号 {llmReviewProgress.current_index || "—"}</small><strong>{llmReviewProgress.current_sample || "正在准备样本"}</strong></span><span><small>已耗时</small><strong>{formatLiveDuration(llmReviewProgress.elapsed_seconds)}</strong></span><span><small>预计剩余</small><strong>{llmReviewProgress.estimated_remaining_seconds == null ? "计算中" : llmReviewProgress.estimated_remaining_seconds <= 0 ? "即将完成" : formatLiveDuration(llmReviewProgress.estimated_remaining_seconds)}</strong></span></div>{llmReviewProgress.error && <p>{llmReviewProgress.error}</p>}</div>}<div className="filter-bar"><div className="type-filters"><button className={filter === "all" ? "active" : ""} onClick={() => onFilter("all")}>全部 <b>{totalFindings}</b></button>{Object.entries(vulnerabilityNames).map(([key, label]) => <button className={filter === key ? "active" : ""} onClick={() => onFilter(key)} key={key}>{label}</button>)}</div><div className="review-filters"><FindingFilterSelect label="LLM 复核" ariaLabel="LLM 复核状态" value={llmFilter} options={llmOptions} onChange={onLlmFilter} /><FindingFilterSelect label="人工验证" ariaLabel="人工验证状态" value={manualFilter} options={manualOptions} onChange={onManualFilter} /></div><div className="export-links">{selectedScanId && <><a href={`${API_BASE}/api/scans/${selectedScanId}/export.json`} target="_blank" rel="noreferrer">导出 JSON</a><a href={`${API_BASE}/api/scans/${selectedScanId}/export.csv`} target="_blank" rel="noreferrer">导出 CSV</a></>}</div></div>{findings.length ? <><div className="finding-table-head"><label className="finding-check"><input type="checkbox" aria-label="全选当前结果" checked={allSelected} onChange={toggleAll} /><i /></label><span className="finding-selection-summary">已选择 <strong>{selectedIds.length}</strong> 条</span><span>LLM 复核</span><span>人工验证</span><span /></div><div className="finding-list">{findings.map((finding) => <div role="button" tabIndex={0} className={`finding-row ${selectedIds.includes(finding.id) ? "selected" : ""} ${highlightedFindingId === finding.id ? "recently-updated" : ""}`} key={finding.id} onClick={() => onSelect(finding)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onSelect(finding); }}><label className="finding-check" onClick={(event) => event.stopPropagation()}><input type="checkbox" aria-label={`选择 ${finding.file}:${finding.line}`} checked={selectedIds.includes(finding.id)} onChange={() => toggleFinding(finding.id)} /><i /></label><span className={`finding-icon ${finding.vulnerability_type}`}>{finding.checker.toUpperCase()}</span><div><strong>{vulnerabilityNames[finding.vulnerability_type] || finding.kind}</strong><p>{finding.file}<b>:{finding.line}:{finding.column}</b></p></div><span className={`review-pill llm-review ${llmReviewClass(finding.verdict)}`} title={`LLM 结论：${verdictName(finding.verdict)}`}>{llmReviewName(finding.verdict)}</span><span className={`review-pill manual-review ${manualReviewClass(finding.review_status)}`}>{manualReviewName(finding.review_status)}</span><em>›</em></div>)}</div></> : <EmptyState title={selectedScanId && hasFindings ? "没有符合筛选条件的结果" : selectedScanId ? "当前扫描没有漏洞结果" : "请选择扫描任务"} text={selectedScanId && hasFindings ? "请调整漏洞类型、LLM 复核或人工验证筛选条件。" : selectedScanId ? "检测完成且无报告，或任务尚未运行到结果解析阶段。" : "完成扫描后可在此查看源码证据。"} />}</section>;
}

function FindingDrawer({ finding, busy, onClose, onReview }: { finding: Finding; busy: boolean; onClose: () => void; onReview: (status: string) => void }) {
  const [source, setSource] = useState<SourceView | null>(null);
  const [sourceError, setSourceError] = useState("");
  const [loading, setLoading] = useState(true);
  const [focusLine, setFocusLine] = useState(finding.line);
  const reviewed = ["true_positive", "false_positive"].includes(finding.verdict);
  const reviewResultId = `review-result-${finding.id}`;

  useEffect(() => {
    const bodyOverflow = document.body.style.overflow;
    const bodyPaddingRight = document.body.style.paddingRight;
    const rootOverflow = document.documentElement.style.overflow;
    const scrollbarWidth = Math.max(0, window.innerWidth - document.documentElement.clientWidth);
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
    if (scrollbarWidth) document.body.style.paddingRight = `${scrollbarWidth}px`;
    return () => {
      document.body.style.overflow = bodyOverflow;
      document.body.style.paddingRight = bodyPaddingRight;
      document.documentElement.style.overflow = rootOverflow;
    };
  }, []);

  const loadSource = useCallback(async (file?: string, line?: number) => {
    setLoading(true);
    setSourceError("");
    if (line) setFocusLine(line);
    try {
      const query = file ? `?file=${encodeURIComponent(file)}` : "";
      setSource(await api<SourceView>(`/api/findings/${finding.id}/source${query}`));
    } catch (error) {
      setSourceError(error instanceof Error ? error.message : "无法读取源码");
    } finally {
      setLoading(false);
    }
  }, [finding.id]);

  useEffect(() => { const timer = window.setTimeout(() => void loadSource(undefined, finding.line), 0); return () => window.clearTimeout(timer); }, [finding.id, finding.line, loadSource]);
  useEffect(() => {
    if (!source || !focusLine) return;
    window.setTimeout(() => document.getElementById(`source-${finding.id}-${focusLine}`)?.scrollIntoView({ block: "center" }), 0);
  }, [source, focusLine, finding.id]);

  function jumpToReviewResult() {
    document.getElementById(reviewResultId)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return <div className="drawer-backdrop" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}><aside className="drawer source-drawer"><div className="drawer-head"><div><span className="section-tag">{finding.checker.toUpperCase()}</span><h2>{vulnerabilityNames[finding.vulnerability_type] || finding.kind}</h2><p>{finding.kind}</p></div><button className="icon-button" onClick={onClose} aria-label="关闭">×</button></div><div className="location-card"><span>漏洞位置</span><strong>{finding.file}</strong><code>line {finding.line}, column {finding.column}</code></div>
    <div className="drawer-section source-section"><div className="source-heading"><div><h3>源码与调用路径</h3><p>{source?.path || "正在定位项目源码…"}</p></div>{source && <span>{source.language.toUpperCase()} · {source.total_lines} 行</span>}</div>
      {(reviewed || source?.locations.length) ? <div className="location-trail">{reviewed && <button className="review-result" onClick={jumpToReviewResult}><i /><span>复核结果</span><code>{llmReviewName(finding.verdict)}</code></button>}{source?.locations.filter((location) => location.role !== "evidence").map((location, index) => <button disabled={!location.available} className={location.role} key={`${location.path}-${location.line}-${index}`} onClick={() => void loadSource(location.path, location.line)}><i /> <span>{location.label}</span><code>{location.path}:{location.line}</code></button>)}</div> : null}
      {loading && <div className="source-loading">读取源码…</div>}
      {sourceError && <div className="source-error">{sourceError}</div>}
      {source && !loading && <div className="source-viewer" role="region" aria-label="源码在线查看">{source.lines.map((line) => <div id={`source-${finding.id}-${line.number}`} className={`source-line ${line.roles.join(" ")}`} key={line.number}><span>{line.number}</span><code>{line.text || " "}</code></div>)}</div>}
      {source?.truncated && <p className="source-warning">文件过长，仅显示前 50,000 行。</p>}
    </div>
    <div className="drawer-section"><h3>原始报告</h3><pre className="raw-block">{finding.raw_text}</pre></div>
    {reviewed && <div id={reviewResultId} className="drawer-section llm-result-section"><div className="llm-result-heading"><div><h3>LLM 复核结果</h3><p>基于 Saber 报告、调用路径和源码切片生成</p></div></div><div className="llm-result-metrics"><div><span>复核判断</span><strong className={llmReviewClass(finding.verdict)}>{verdictName(finding.verdict)}</strong></div><div><span>置信度</span><strong>{Math.round(finding.confidence * 100)}%</strong></div></div><div className="llm-result-copy"><span>判断依据</span><p>{finding.rationale || "模型未返回判断依据。"}</p></div>{finding.evidence.length > 0 && <div className="llm-evidence-list"><span>关键证据</span><ul>{finding.evidence.map((item, index) => <li key={`${item.file}-${item.line}-${index}`}><code>{item.file}:{item.line}</code><b>{llmEvidenceRoleName(item.role)}</b></li>)}</ul></div>}{finding.fix_suggestion && <div className="llm-result-copy suggestion"><span>修复建议</span><p>{finding.fix_suggestion}</p></div>}</div>}
    <div className="review-actions"><button disabled={busy} onClick={() => onReview("confirmed")}>确认漏洞</button><button disabled={busy} onClick={() => onReview("false_positive")}>标记误报</button></div></aside></div>;
}

function StatisticsPanel({ statistics, projects, onReload }: { statistics: ScanStatistics; projects: Project[]; onReload: (value: ScanStatistics) => void }) {
  const [projectId, setProjectId] = useState("");
  const [loading, setLoading] = useState(false);
  async function changeProject(value: string) {
    setProjectId(value);
    setLoading(true);
    try {
      onReload(await api<ScanStatistics>(`/api/statistics${value ? `?project_id=${encodeURIComponent(value)}` : ""}`));
    } finally {
      setLoading(false);
    }
  }
  return <div className="content-stack statistics-page">
    <section className="section-head stats-filter"><div><h2>结果统计面板</h2><p>检测结果、扫描耗时、Bitcode 数量、源文件数量与复核状态。</p></div><StatisticsProjectFilter projects={projects} value={projectId} loading={loading} onChange={(value) => void changeProject(value)} /></section>
    <section className="metric-grid stats-metrics"><Metric label="统计扫描" value={statistics.summary.scans} note={`${statistics.summary.completed_scans} 个已完成`} /><Metric label="Bitcode 数量" value={statistics.summary.bitcode_count} note="当前统计范围内生成总数" /><Metric label="源文件数量" value={statistics.summary.source_file_count} note="当前项目范围内的源码文件" /><div className="metric"><span>平均扫描耗时</span><strong className="metric-size">{formatDuration(statistics.summary.avg_duration_seconds)}</strong><small>从任务开始到结束</small></div></section>
    <section className="stats-grid"><div className="panel stats-card"><PanelHeader title="漏洞类型分布" subtitle="按 CWE 分类展示当前筛选范围内的结果" />{statistics.by_type.length ? <VulnerabilityPie items={statistics.by_type} /> : <p className="muted stats-empty">暂无漏洞结果</p>}</div><div className="panel stats-card"><PanelHeader title="复核状态概览" subtitle="展示 LLM 复核与人工验证的处理进度" /><ReviewStatusOverview data={statistics.review_status} /></div></section>
    <section className="panel full stats-table"><PanelHeader title="最近扫描指标" subtitle="分别展示每次任务生成的 Bitcode 和项目源文件数量" />{statistics.recent_scans.length ? <div className="table-wrap"><table><thead><tr><th>项目 / 任务</th><th>状态</th><th>Bitcode 数量</th><th>源文件数量</th><th>耗时</th><th>漏洞结果</th><th>扫描时间</th></tr></thead><tbody>{statistics.recent_scans.map((scan) => <tr key={scan.id}><td><strong>{scan.project_name}</strong><br /><code>{shortId(scan.id)}</code></td><td><span className={`status-pill ${scan.status}`}>{statusName(scan.status)}</span></td><td>{scan.bitcode_count}</td><td>{scan.source_file_count}</td><td>{formatDuration(scan.duration_seconds)}</td><td>{scan.finding_count}</td><td>{formatDate(scan.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState title="暂无统计数据" text="完成一次扫描后，这里会展示 Bitcode、源文件数量和复核状态。" />}</section>
  </div>;
}

function ReviewStatusOverview({ data }: { data: ScanStatistics["review_status"] }) {
  const llmItems = [["true_positive", "已通过"], ["false_positive", "未通过"], ["unreviewed", "未复核"]] as const;
  const manualItems = [["confirmed", "已验证"], ["false_positive", "已标误报"], ["pending", "未验证"]] as const;
  const total = Math.max(1, Object.values(data.llm).reduce((sum, count) => sum + count, 0));
  const llmHandled = (data.llm.true_positive || 0) + (data.llm.false_positive || 0);
  const manuallyHandled = (data.manual.confirmed || 0) + (data.manual.false_positive || 0);
  const llmReviewRate = Math.round(llmHandled / total * 100);
  const manualReviewRate = Math.round(manuallyHandled / total * 100);
  const renderGroup = (title: string, items: readonly (readonly [string, string])[], values: Record<string, number>) => <div className="review-stat-group"><h3>{title}</h3>{items.map(([key, label]) => { const count = values[key] || 0; return <div className={`review-stat-row ${key}`} key={key}><span>{label}</span><div><i style={{ width: `${count / total * 100}%` }} /></div><strong>{count}</strong></div>; })}</div>;
  if (!Object.keys(data.llm).length && !Object.keys(data.manual).length) return <p className="muted stats-empty">暂无复核数据</p>;
  return <div className="review-stat-overview">{renderGroup("LLM 复核", llmItems, data.llm)}{renderGroup("人工验证", manualItems, data.manual)}<div className="review-rate-summary"><div><span>LLM 处理率</span><strong>{llmReviewRate}%</strong><small>{llmHandled} / {total} 条已归类</small></div><div><span>人工处理率</span><strong>{manualReviewRate}%</strong><small>{manuallyHandled} / {total} 条已处理</small></div></div><p className="review-status-note">接口异常、证据不足或模型未形成有效结论时，界面统一计为“未通过”；原始状态仍保留用于诊断与重试。</p></div>;
}

function StatisticsProjectFilter({ projects, value, loading, onChange }: { projects: Project[]; value: string; loading: boolean; onChange: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const selected = projects.find((project) => project.id === value);

  useEffect(() => {
    function closeOnOutsideClick(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  function choose(nextValue: string) {
    setOpen(false);
    if (nextValue !== value) onChange(nextValue);
  }

  return <div ref={rootRef} className={`stats-project-select ${open ? "open" : ""}`}>
    <button type="button" className="stats-project-trigger" aria-label="统计项目范围" aria-haspopup="listbox" aria-expanded={open} disabled={loading} onClick={() => setOpen((current) => !current)}>
      <span>统计范围</span><strong>{selected?.name || "全部项目"}</strong><i aria-hidden />
    </button>
    {open && <div className="stats-project-menu" role="listbox" aria-label="选择统计项目">
      <button type="button" role="option" aria-selected={!value} className={!value ? "selected" : ""} onClick={() => choose("")}><span><strong>全部项目</strong><small>汇总所有项目的扫描数据</small></span><i aria-hidden>✓</i></button>
      {projects.map((project) => <button type="button" role="option" aria-selected={project.id === value} className={project.id === value ? "selected" : ""} key={project.id} onClick={() => choose(project.id)}><span><strong>{project.name}</strong><small>{project.build_system || "待识别构建系统"}</small></span><i aria-hidden>✓</i></button>)}
    </div>}
  </div>;
}

function VulnerabilityPie({ items }: { items: Array<{ type: string; count: number }> }) {
  const [activeType, setActiveType] = useState<string | null>(null);
  const total = items.reduce((sum, item) => sum + item.count, 0);
  const active = items.find((item) => item.type === activeType) || null;

  function selectSegment(event: ReactMouseEvent<HTMLDivElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - bounds.left - bounds.width / 2;
    const y = event.clientY - bounds.top - bounds.height / 2;
    const distance = Math.sqrt(x * x + y * y);
    if (distance < bounds.width * 0.285 || distance > bounds.width / 2) {
      setActiveType(null);
      return;
    }
    const angle = (Math.atan2(y, x) * 180 / Math.PI + 90 + 360) % 360;
    let boundary = 0;
    const match = items.find((item) => {
      boundary += item.count / total * 360;
      return angle <= boundary;
    });
    setActiveType(match?.type || null);
  }

  return <div className="pie-layout"><div className={`pie-chart ${active ? "has-active" : ""}`} style={{ background: vulnerabilityPieGradient(items, activeType) }} role="img" aria-label={active ? `${vulnerabilityNames[active.type] || active.type} ${active.count} 条` : `漏洞类型数量饼状图，共 ${total} 条`} onMouseMove={selectSegment} onMouseLeave={() => setActiveType(null)}><div><strong>{active?.count ?? total}</strong><span>{active ? vulnerabilityNames[active.type] || active.type : "漏洞结果"}</span><small>{active ? vulnerabilityCwes[active.type] || "CWE-Other" : "悬停查看详情"}</small></div></div><div className="pie-legend">{items.map((item) => <button type="button" className={activeType === item.type ? "active" : ""} key={item.type} onMouseEnter={() => setActiveType(item.type)} onMouseLeave={() => setActiveType(null)} onFocus={() => setActiveType(item.type)} onBlur={() => setActiveType(null)}><i style={{ backgroundColor: vulnerabilityColors[item.type] || "#82918a" }} /><span><strong>{vulnerabilityNames[item.type] || item.type}</strong><small>{vulnerabilityCwes[item.type] || "CWE-Other"} · {Math.round(item.count / total * 100)}%</small></span><b>{item.count}</b></button>)}</div></div>;
}

function MemoryFunctionsModal({ project, busy, onClose, onNotice }: { project: Project; busy: boolean; onClose: () => void; onNotice: (message: string) => void }) {
  const [allocText, setAllocText] = useState("");
  const [freeText, setFreeText] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const apply = (value: MemoryFunctions) => { setAllocText(value.alloc_functions.join("\n")); setFreeText(value.free_functions.join("\n")); };
  useEffect(() => {
    void api<MemoryFunctions>(`/api/projects/${project.id}/memory-functions`).then(apply).catch((reason: Error) => setError(reason.message)).finally(() => setLoading(false));
  }, [project.id]);
  const names = (text: string) => text.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  async function save() {
    setSaving(true); setError("");
    try {
      const saved = await api<MemoryFunctions>(`/api/projects/${project.id}/memory-functions`, { method: "PUT", body: JSON.stringify({ alloc_functions: names(allocText), free_functions: names(freeText) }) });
      apply(saved); onNotice(`已保存 ${saved.alloc_functions.length} 个分配函数和 ${saved.free_functions.length} 个释放函数`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "保存失败"); }
    finally { setSaving(false); }
  }
  async function importFile(file: File | null) {
    if (!file) return;
    setSaving(true); setError("");
    try {
      const form = new FormData(); form.append("config", file);
      const saved = await api<MemoryFunctions>(`/api/projects/${project.id}/memory-functions/import`, { method: "POST", body: form });
      apply(saved); onNotice(`已从 ${file.name} 导入 ${saved.alloc_functions.length + saved.free_functions.length} 个函数`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "导入失败"); }
    finally { setSaving(false); }
  }
  return <Modal title={`内存函数 · ${project.name}`} subtitle="扫描任务创建时会保存配置快照，并通过 Saber -api-config 加载" onClose={onClose}><div className="memory-help"><strong>支持手动填写或导入 JSON / CSV / TXT</strong><span>文本格式示例：<code>alloc: pool_alloc</code>、<code>free: pool_release</code>；每行一个，也可用逗号分隔。</span><span>当前 Web 版本不会自动调用 LLM 识别函数。</span></div>{error && <div className="modal-error">{error}</div>}<div className="memory-function-grid"><Field label="自定义分配函数"><textarea disabled={loading} value={allocText} onChange={(event) => setAllocText(event.target.value)} placeholder={"pool_alloc\narena_create"} spellCheck={false} /></Field><Field label="自定义释放函数"><textarea disabled={loading} value={freeText} onChange={(event) => setFreeText(event.target.value)} placeholder={"pool_free\narena_destroy"} spellCheck={false} /></Field></div><div className="memory-import"><label className="button secondary">从文件导入<input type="file" accept=".json,.csv,.txt,.conf" onChange={(event) => void importFile(event.target.files?.[0] || null)} /></label><span>导入会替换当前项目的函数配置。</span></div><div className="memory-actions"><button className="button" onClick={onClose}>关闭</button><button disabled={busy || saving || loading} className="button primary" onClick={() => void save()}>{saving ? "保存中…" : "保存配置"}</button></div></Modal>;
}

type ProjectPayload = { mode: "local"; name: string; source_path: string } | { mode: "git"; name: string; repository_url: string; ref: string } | { mode: "upload"; name: string; archive: File };
async function createProject(payload: ProjectPayload) {
  if (payload.mode === "upload") { const form = new FormData(); form.append("name", payload.name); form.append("archive", payload.archive); return api<Project>("/api/projects/upload", { method: "POST", body: form }); }
  if (payload.mode === "git") return api<Project>("/api/projects/git", { method: "POST", body: JSON.stringify(payload) });
  return api<Project>("/api/projects/local", { method: "POST", body: JSON.stringify(payload) });
}

function ProjectModal({ busy, onClose, onSubmit }: { busy: boolean; onClose: () => void; onSubmit: (payload: ProjectPayload) => void }) {
  const [mode, setMode] = useState<"local" | "upload" | "git">("local"); const [name, setName] = useState(""); const [path, setPath] = useState(""); const [url, setUrl] = useState(""); const [ref, setRef] = useState(""); const [file, setFile] = useState<File | null>(null);
  function submit(event: FormEvent) { event.preventDefault(); if (mode === "local") onSubmit({ mode, name, source_path: path }); else if (mode === "git") onSubmit({ mode, name, repository_url: url, ref }); else if (file) onSubmit({ mode, name, archive: file }); }
  return <Modal title="导入分析项目" subtitle="源码只保存在本机工作目录" onClose={onClose}><div className="tab-switch">{(["local", "upload", "git"] as const).map((item) => <button className={mode === item ? "active" : ""} onClick={() => setMode(item)} key={item}>{item === "local" ? "本地目录" : item === "upload" ? "源码压缩包" : "公开 Git"}</button>)}</div><form onSubmit={submit} className="form-stack"><Field label="项目名称（可选）"><input value={name} onChange={(event) => setName(event.target.value)} placeholder="例如 libcurl" /></Field>{mode === "local" && <Field label="本地源码目录"><input required value={path} onChange={(event) => setPath(event.target.value)} placeholder="/home/me/project 或 E:\source\project" /><small>服务会引用该目录，不会复制或修改源码。</small></Field>}{mode === "upload" && <Field label="源码压缩包"><label className="file-drop"><input required type="file" accept=".zip,.tar,.gz,.tgz,.xz" onChange={(event) => setFile(event.target.files?.[0] || null)} /><strong>{file ? file.name : "选择 ZIP / TAR 源码包"}</strong><span>自动进行路径安全检查并解压到本地数据目录</span></label></Field>}{mode === "git" && <><Field label="公开仓库地址"><input required type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://github.com/org/project.git" /></Field><Field label="分支 / Tag（可选）"><input value={ref} onChange={(event) => setRef(event.target.value)} placeholder="main" /></Field></>}<div className="modal-actions"><button type="button" className="button" onClick={onClose}>取消</button><button disabled={busy} className="button primary">{busy ? "正在导入…" : "导入项目"}</button></div></form></Modal>;
}

function ScanModal({ project, busy, defaultParallelism, defaultLlmParallelism, onClose, onSubmit }: { project: Project; busy: boolean; defaultParallelism: number; defaultLlmParallelism: number; onClose: () => void; onSubmit: (payload: { checkers: string[]; verify_enabled: boolean; parallelism: number; llm_parallelism: number }) => void }) {
  const [checkers, setCheckers] = useState(["leak", "dfree", "uaf", "fileck", "npd"]); const [verify, setVerify] = useState(false); const [parallelism, setParallelism] = useState(defaultParallelism); const [llmParallelism, setLlmParallelism] = useState(defaultLlmParallelism);
  return <Modal title={`扫描 ${project.name}`} subtitle={`${project.build_system} · ${project.source_files} 个源文件`} onClose={onClose}><div className="checker-grid">{checkerInfo.map((checker) => <label className={checkers.includes(checker.id) ? "selected" : ""} key={checker.id}><input type="checkbox" checked={checkers.includes(checker.id)} onChange={() => setCheckers((current) => current.includes(checker.id) ? current.filter((item) => item !== checker.id) : [...current, checker.id])} /><b>{checker.code}</b><span>{checker.label}</span></label>)}</div><div className="scan-parallelism"><Field label="并行检测进程"><input type="number" min={1} max={16} value={parallelism} onChange={(event) => setParallelism(Math.max(1, Math.min(16, Number(event.target.value) || 1)))} /><small>每一路运行一个独立 Saber 子进程，默认值按 CPU 与内存计算。</small></Field>{verify && <Field label="LLM 复核并发线程"><input type="number" min={1} max={16} value={llmParallelism} onChange={(event) => setLlmParallelism(Math.max(1, Math.min(16, Number(event.target.value) || 1)))} /><small>HTTP 请求采用多线程并发；请同时考虑模型服务的并发上限。</small></Field>}</div><div className="option-list"><Toggle checked={verify} onChange={setVerify} title="启用漏洞 LLM 复核" text="对 Saber 报告、路径和源码切片进行可行性判断。" /></div><div className="modal-actions scan-modal-actions"><button className="button" onClick={onClose}>取消</button><button disabled={busy || !checkers.length} className="button primary" onClick={() => onSubmit({ checkers, verify_enabled: verify, parallelism, llm_parallelism: llmParallelism })}>{busy ? "正在创建…" : "开始扫描"}</button></div></Modal>;
}

function SettingsPanel({ settings, system, onSave }: { settings: Settings; system: SystemStatus | null; onSave: (settings: Settings) => void }) {
  const [form, setForm] = useState(() => ({
    ...settings,
    llm_api_key: settings.llm_api_key || (settings.llm_api_key_configured ? SAVED_API_KEY_MASK : ""),
  }));
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const set = (key: keyof Settings, value: string | number) => {
    setTestResult(null);
    setForm((current) => ({ ...current, [key]: value }));
  };
  async function testConnection() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api<LLMConnectionTestResult>("/api/settings/llm/test", {
        method: "POST",
        body: JSON.stringify({
          llm_model: form.llm_model,
          llm_base_url: form.llm_base_url,
          llm_chat_path: form.llm_chat_path,
          llm_api_key_env: form.llm_api_key_env,
          llm_api_key: form.llm_api_key === SAVED_API_KEY_MASK ? "" : form.llm_api_key,
          llm_timeout: Math.min(120, Math.max(5, form.llm_timeout)),
        }),
      });
      setTestResult({ ok: true, message: `${result.message} · ${result.authenticated ? "API Key 鉴权" : "无需 API Key"}` });
    } catch (error) {
      setTestResult({ ok: false, message: error instanceof Error ? error.message : "LLM API 连接失败" });
    } finally {
      setTesting(false);
    }
  }
  const llmReady = Boolean(system?.llm.configured);
  return <div className="settings-grid"><section className="panel"><div className="section-head"><div><h2>分析工具链</h2><p>路径留空时使用环境变量或默认目录。</p></div></div><div className="form-grid"><Field label="SVF 构建目录"><input value={form.svf_build_dir} onChange={(event) => set("svf_build_dir", event.target.value)} placeholder="SVF/Release-build" /></Field><Field label="Saber 可执行文件"><input value={form.saber_path} onChange={(event) => set("saber_path", event.target.value)} placeholder=".../bin/saber" /></Field><Field label="extapi.bc"><input value={form.extapi_path} onChange={(event) => set("extapi_path", event.target.value)} placeholder=".../lib/extapi.bc" /></Field><div className="split-fields"><Field label="Clang"><input value={form.clang} onChange={(event) => set("clang", event.target.value)} /></Field><Field label="Clang++"><input value={form.clangxx} onChange={(event) => set("clangxx", event.target.value)} /></Field></div><div className="split-fields"><Field label="构建超时（秒）"><input type="number" value={form.build_timeout} onChange={(event) => set("build_timeout", Number(event.target.value))} /></Field><Field label="单次检测超时"><input type="number" value={form.saber_timeout} onChange={(event) => set("saber_timeout", Number(event.target.value))} /></Field></div><Field label="默认并行检测进程"><div className="input-with-hint"><input type="number" min={1} max={16} value={form.scan_parallelism} onChange={(event) => set("scan_parallelism", Math.max(1, Math.min(16, Number(event.target.value) || 1)))} /><small title="单次扫描创建时仍可调整">建议 {system?.hardware.recommended_scan_parallelism || "—"} 路</small></div></Field></div></section><section className="panel llm-settings-panel"><div className="section-head"><div><h2>LLM 漏洞复核</h2><p>用于对静态分析报告、调用路径和源码证据进行语义复核。</p></div><span className={`status-pill ${llmReady ? "completed" : "failed"}`}>{llmReady && system ? llmConfigurationLabel(system.llm) : "尚未配置"}</span></div><div className="form-grid"><Field label="模型"><input value={form.llm_model} onChange={(event) => set("llm_model", event.target.value)} /></Field><Field label="OpenAI 兼容 Base URL"><input value={form.llm_base_url} onChange={(event) => set("llm_base_url", event.target.value)} placeholder="http://host.docker.internal:11434/v1" /><small>模型运行在 Windows 宿主机时，可填写 localhost；OneCVE 会在 Docker 中自动转换为 host.docker.internal。</small></Field><Field label="Chat 路径"><input value={form.llm_chat_path} onChange={(event) => set("llm_chat_path", event.target.value)} /></Field><Field label="API Key"><input type="password" autoComplete="new-password" value={form.llm_api_key} onFocus={() => { if (form.llm_api_key === SAVED_API_KEY_MASK) set("llm_api_key", ""); }} onChange={(event) => set("llm_api_key", event.target.value)} placeholder={form.llm_api_key_configured ? "已保存；留空保持不变" : "本地无鉴权 API 可留空"} /><small>已保存的密钥以掩码显示；密钥仅保存在本地 OneCVE 数据库，接口不会返回明文。</small></Field><div className="split-fields"><Field label="单请求超时（秒）"><input type="number" min={10} max={1800} value={form.llm_timeout} onChange={(event) => set("llm_timeout", Math.max(10, Math.min(1800, Number(event.target.value) || 120)))} /></Field><Field label="默认并发线程"><div className="input-with-hint"><input type="number" min={1} max={16} value={form.llm_parallelism} onChange={(event) => set("llm_parallelism", Math.max(1, Math.min(16, Number(event.target.value) || 1)))} /><small title="扫描配置中可覆盖">建议 {system?.hardware.recommended_llm_parallelism || "—"} 路</small></div></Field></div><div className="llm-test-row"><button type="button" disabled={testing || !form.llm_model || !form.llm_base_url || !form.llm_chat_path} className="button secondary" onClick={() => void testConnection()}>{testing ? "正在测试…" : "测试 API 连接"}</button>{testResult && <span className={testResult.ok ? "success" : "error"}>{testResult.ok ? "✓" : "!"} {testResult.message}</span>}</div></div></section><div className="settings-save"><span>数据目录：<code>{system?.data_root || "—"}</code></span><button className="button primary" onClick={() => onSave({ ...form, llm_api_key: form.llm_api_key === SAVED_API_KEY_MASK ? "" : form.llm_api_key })}>保存本地设置</button></div></div>;
}

function Modal({ title, subtitle, onClose, children }: { title: string; subtitle: string; onClose: () => void; children: React.ReactNode }) { return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="modal" role="dialog" aria-modal="true"><div className="modal-head"><div><h2>{title}</h2><p>{subtitle}</p></div><button className="icon-button" onClick={onClose} aria-label="关闭">×</button></div>{children}</section></div>; }
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="field"><span>{label}</span>{children}</label>; }
function Toggle({ checked, onChange, title, text }: { checked: boolean; onChange: (value: boolean) => void; title: string; text: string }) { return <label className="toggle-row"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i /><div><strong>{title}</strong><p>{text}</p></div></label>; }
function EmptyState({ title, text, action, onAction }: { title: string; text: string; action?: string; onAction?: () => void }) { return <div className="empty"><span>＋</span><h3>{title}</h3><p>{text}</p>{action && <button className="button compact" onClick={onAction}>{action}</button>}</div>; }
function viewTitle(view: View) { return ({ overview: "安全分析总览", projects: "项目管理", scans: "扫描任务", findings: "漏洞结果", statistics: "结果统计", settings: "本地设置" })[view]; }
function sourceKind(kind: string) { return ({ local: "本地目录", upload: "源码包", git: "Git" } as Record<string, string>)[kind] || kind; }
function statusName(status: string) { return ({ queued: "等待", running: "运行中", completed: "已完成", failed: "失败", cancelled: "已取消", cancelling: "停止中" } as Record<string, string>)[status] || status; }
function verdictName(verdict: string) { return ({ true_positive: "已通过", false_positive: "未通过", unknown: "未通过", unreviewed: "未复核" } as Record<string, string>)[verdict] || verdict; }
function llmReviewName(verdict: string) { return ({ true_positive: "已通过", false_positive: "未通过", unknown: "未通过", unreviewed: "未复核" } as Record<string, string>)[verdict] || "未复核"; }
function llmReviewClass(verdict: string) { return ({ true_positive: "passed", false_positive: "rejected", unknown: "rejected", unreviewed: "unreviewed" } as Record<string, string>)[verdict] || "unreviewed"; }
function llmEvidenceRoleName(role: string) { return ({ allocation: "分配", free: "释放", release: "释放", deallocation: "释放", condition: "条件", return: "返回", ownership: "所有权", dereference: "解引用", open: "打开资源", close: "关闭资源" } as Record<string, string>)[role.toLowerCase()] || role; }
function manualReviewName(status: string) { return ({ pending: "未验证", confirmed: "已验证", false_positive: "误报", ignored: "已忽略" } as Record<string, string>)[status] || "未验证"; }
function manualReviewClass(status: string) { return ({ pending: "unverified", confirmed: "verified", false_positive: "false-positive", ignored: "ignored" } as Record<string, string>)[status] || "unverified"; }
function llmConfigurationLabel(llm: SystemStatus["llm"]) { if (llm.authenticated) return "API Key 已发现"; if (llm.local_endpoint) return "本地 API 已配置"; return "无 Key API 已配置"; }
function formatDuration(seconds: number) { if (!seconds) return "—"; if (seconds < 60) return `${Math.round(seconds)} 秒`; const minutes = Math.floor(seconds / 60); return minutes < 60 ? `${minutes} 分 ${Math.round(seconds % 60)} 秒` : `${Math.floor(minutes / 60)} 小时 ${minutes % 60} 分`; }
function formatLiveDuration(seconds: number) { if (!Number.isFinite(seconds) || seconds < 1) return "少于 1 秒"; return formatDuration(seconds); }
function formatProgress(progress: number) { return `${Number.isInteger(progress) ? progress : progress.toFixed(1)}%`; }
function remainingTimeLabel(scan: Scan) {
  if (scan.status === "queued") return "等待调度";
  if (scan.status === "completed") return "任务已完成";
  if (scan.status === "failed") return "任务已停止";
  if (["cancelled", "cancelling"].includes(scan.status)) return scan.status === "cancelling" ? "正在停止" : "任务已取消";
  return scan.estimated_remaining_seconds ? `预计剩余 ${formatDuration(scan.estimated_remaining_seconds)}` : "正在估算剩余时间";
}

const stageSummaryMessages: Record<string, string> = {
  queued: "扫描任务已进入本地队列",
  preparing: "正在准备项目与扫描目录",
  building: "正在生成 LLVM Bitcode",
  analyzing: "正在执行漏洞扫描",
  parsing: "正在解析并去重检测结果",
  verifying: "正在复核漏洞证据",
  cancelling: "正在停止扫描任务",
  cancelled: "扫描任务已取消",
  completed: "扫描任务已完成",
  failed: "扫描任务执行失败，请查看任务诊断",
  interrupted: "扫描任务因服务中断而停止",
  cleanup: "正在清理项目构建产物",
};

function summarizeScanEvents(events: ScanEvent[]): ScanEvent[] {
  const seen = new Set<string>();
  const summary: ScanEvent[] = [];
  for (const event of events) {
    if (seen.has(event.stage)) continue;
    seen.add(event.stage);
    summary.push({
      ...event,
      level: ["failed", "cancelled", "interrupted"].includes(event.stage) ? "warning" : "info",
      message: stageSummaryMessages[event.stage] || `正在执行${stageNames[event.stage] || event.stage}`,
    });
  }
  return summary;
}

function vulnerabilityPieGradient(items: Array<{ type: string; count: number }>, activeType: string | null = null): string {
  const total = items.reduce((sum, item) => sum + item.count, 0);
  if (!total) return "#e5ebe7";
  let offset = 0;
  const segments = items.map((item) => {
    const start = offset;
    offset += item.count / total * 100;
    const baseColor = vulnerabilityColors[item.type] || "#82918a";
    const color = activeType && activeType !== item.type ? `${baseColor}59` : baseColor;
    return `${color} ${start.toFixed(2)}% ${offset.toFixed(2)}%`;
  });
  return `conic-gradient(${segments.join(", ")})`;
}
