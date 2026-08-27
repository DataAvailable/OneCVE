export const API_BASE =
  process.env.NEXT_PUBLIC_NSPA_API_URL ?? "http://127.0.0.1:8000";

export type Project = {
  id: string;
  name: string;
  source_kind: string;
  source_path: string;
  build_system: string;
  source_files: number;
  scan_count: number;
  finding_count: number;
  latest_scan_status?: string | null;
  created_at: string;
};

export type Scan = {
  id: string;
  project_id: string;
  project_name: string;
  status: string;
  stage: string;
  progress: number;
  estimated_remaining_seconds?: number | null;
  checkers: string[];
  verify_enabled: boolean;
  scan_parallelism: number;
  llm_parallelism: number;
  build_strategy?: string | null;
  bitcode_count: number;
  source_unit_count: number;
  finding_count: number;
  custom_alloc: string[];
  custom_free: string[];
  error?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
};

export type Finding = {
  id: string;
  scan_id: string;
  checker: string;
  kind: string;
  vulnerability_type: string;
  file: string;
  line: number;
  column: number;
  verdict: string;
  confidence: number;
  rationale: string;
  fix_suggestion: string;
  path: Array<{ file: string; line: number; column: number; branch?: string }>;
  evidence: Array<{ file: string; line: number; role: string }>;
  snippets: Array<{
    file: string;
    start_line: number;
    end_line: number;
    important_lines: number[];
    text: string;
  }>;
  raw_text: string;
  review_status: string;
};

export type ScanEvent = {
  id: number;
  level: string;
  stage: string;
  message: string;
  created_at: string;
};

export type LLMReviewProgress = {
  scan_id: string;
  active: boolean;
  total: number;
  completed: number;
  percent: number;
  current_index: number;
  current_finding_id: string;
  current_sample: string;
  elapsed_seconds: number;
  estimated_remaining_seconds: number | null;
  error?: string | null;
};

export type StorageStatus = {
  filesystem: { total_bytes: number; used_bytes: number; free_bytes: number };
  onecve: {
    data_bytes: number;
    projects_bytes: number;
    scans_bytes: number;
    database_bytes: number;
    build_bytes: number;
    reports_bytes: number;
    reclaimable_bytes: number;
  };
  projects: Array<{
    project_id: string;
    managed_source_bytes: number;
    scan_bytes: number;
    build_bytes: number;
    total_bytes: number;
    source_managed: boolean;
  }>;
};

export type MemoryFunctions = {
  project_id: string;
  alloc_functions: string[];
  free_functions: string[];
};

export type SourceLocation = {
  file: string;
  path: string;
  line: number;
  column: number;
  branch?: string | null;
  role: "access" | "release" | "call_path" | "finding" | "evidence";
  label: string;
  available: boolean;
};

export type SourceView = {
  path: string;
  language: string;
  total_lines: number;
  truncated: boolean;
  available_files: string[];
  locations: SourceLocation[];
  lines: Array<{ number: number; text: string; roles: string[] }>;
};

export type ScanStatistics = {
  summary: {
    scans: number;
    completed_scans: number;
    findings: number;
    avg_duration_seconds: number;
    bitcode_count: number;
    source_file_count: number;
  };
  by_type: Array<{ type: string; count: number }>;
  review_status: {
    llm: Record<string, number>;
    manual: Record<string, number>;
  };
  recent_scans: Array<Scan & { duration_seconds: number; source_file_count: number }>;
};

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let message = `请求失败 (${response.status})`;
    try {
      const payload = (await response.json()) as { detail?: string };
      message = payload.detail || message;
    } catch {
      // Keep the HTTP fallback message.
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}

export function shortId(value: string): string {
  return value.slice(0, 8);
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const amount = value / 1024 ** index;
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}
