/**
 * Minimal GitHub REST client.
 *
 * Deliberately dependency-free and deliberately honest: when an endpoint is
 * unavailable to the current token the client returns a typed "unavailable"
 * result rather than throwing, so a control can be reported as unverifiable
 * instead of silently passing.
 */

export interface GhResponse<T> {
  ok: boolean;
  status: number;
  /** Parsed body when ok. */
  data?: T;
  /** Present when ok is false. */
  reason?: string;
}

const API = "https://api.github.com";

export class GitHubClient {
  private token?: string;
  readonly owner: string;
  readonly repo: string;
  private base = API;

  /** Counted so collectors can explain cost and we can stop early. */
  requests = 0;
  private remaining = 5000;

  constructor(
    owner: string,
    repo: string,
    token?: string,
    base = API,
  ) {
    this.owner = owner;
    this.repo = repo;
    this.token = token;
    this.base = base.replace(/\/+$/, "");
  }

  get hasToken(): boolean {
    return Boolean(this.token);
  }

  get rateLimitRemaining(): number {
    return this.remaining;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "auditgen",
    };
    if (this.token) h.Authorization = `Bearer ${this.token}`;
    return h;
  }

  async request<T>(
    path: string,
    init: RequestInit = {},
    attempt = 0,
  ): Promise<GhResponse<T>> {
    if (!this.hasToken) {
      return { ok: false, status: 0, reason: "no token available" };
    }
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    this.requests++;
    let res: Response;
    try {
      res = await fetch(url, { ...init, headers: this.headers() });
    } catch (err) {
      return { ok: false, status: 0, reason: `network: ${String(err)}` };
    }

    const rl = res.headers.get("x-ratelimit-remaining");
    if (rl !== null) this.remaining = Number(rl);

    if (res.status === 403 && rl === "0") {
      if (attempt < 2) {
        const reset = Number(res.headers.get("x-ratelimit-reset") ?? "0");
        const waitMs = Math.max(
          1000,
          reset * 1000 - Date.now() + 500,
        );
        await new Promise((r) => setTimeout(r, Math.min(waitMs, 65_000)));
        return this.request<T>(path, init, attempt + 1);
      }
      return { ok: false, status: 403, reason: "rate limit exhausted" };
    }

    if (res.status === 404) {
      return { ok: false, status: 404, reason: "not found or not accessible" };
    }
    if (res.status === 401) {
      return { ok: false, status: 401, reason: "token rejected" };
    }
    if (res.status === 403) {
      const body = await res.text().catch(() => "");
      const isScope =
        body.includes("Resource not accessible") ||
        body.includes("requires");
      return {
        ok: false,
        status: 403,
        reason: isScope
          ? "token lacks the scope for this endpoint"
          : body.slice(0, 200) || "forbidden",
      };
    }
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        reason: `HTTP ${res.status}`,
      };
    }

    if (res.status === 204) return { ok: true, status: 204 };

    try {
      return { ok: true, status: res.status, data: (await res.json()) as T };
    } catch {
      return { ok: false, status: res.status, reason: "unparseable body" };
    }
  }

  /** Follows Link rel="next" up to maxPages. Returns [] on any failure. */
  async paginate<T>(
    path: string,
    maxPages = 3,
  ): Promise<{ items: T[]; truncated: boolean; error?: string }> {
    const items: T[] = [];
    let next: string | null = `${this.base}${path}`;
    for (let page = 0; page < maxPages && next; page++) {
      const res: GhResponse<T[] | { items?: T[]; next?: string }> =
        await this.request<T[] | { items?: T[]; next?: string }>(next);
      if (!res.ok || !res.data) {
        return {
          items,
          truncated: page > 0,
          ...(res.reason ? { error: res.reason } : {}),
        };
      }
      const batch = Array.isArray(res.data) ? res.data : (res.data.items ?? []);
      items.push(...batch);
      next = Array.isArray(res.data) ? null : (res.data.next ?? null);
      if (batch.length === 0) next = null;
    }
    return { items, truncated: Boolean(next) };
  }

  // ---- Typed helpers for the endpoints auditgen relies on -----------------

  getRepo(): Promise<RepoResponse | undefined> {
    return this.request<RepoResponse>(
      `/repos/${this.owner}/${this.repo}`,
    ).then((r: GhResponse<RepoResponse>) => (r.ok ? r.data : undefined));
  }

  async defaultBranch(): Promise<string | undefined> {
    const r = await this.getRepo();
    return r?.default_branch;
  }

  content(
    path: string,
    ref?: string,
  ): Promise<GhResponse<ContentResponse>> {
    const q = ref ? `?ref=${encodeURIComponent(ref)}` : "";
    return this.request<ContentResponse>(
      `/repos/${this.owner}/${this.repo}/contents/${path}${q}`,
    );
  }

  /**
   * Branch protection. Requires admin or maintain. Returns undefined when the
   * caller cannot see protection settings at all.
   */
  async branchProtection(
    branch: string,
  ): Promise<GhResponse<BranchProtection>> {
    return this.request<BranchProtection>(
      `/repos/${this.owner}/${this.repo}/branches/${encodeURIComponent(branch)}/protection`,
    );
  }

  async dependabotAlerts(): Promise<GhResponse<unknown[]>> {
    return this.request<unknown[]>(
      `/repos/${this.owner}/${this.repo}/dependabot/alerts?per_page=100&state=all`,
    );
  }

  async secretScanningAlerts(): Promise<GhResponse<unknown[]>> {
    return this.request<unknown[]>(
      `/repos/${this.owner}/${this.repo}/secret-scanning/alerts?per_page=100`,
    );
  }

  async securityAdvisories(): Promise<GhResponse<unknown[]>> {
    return this.request<unknown[]>(
      `/repos/${this.owner}/${this.repo}/security-advisories?per_page=100`,
    );
  }

  async actionWorkflows(): Promise<GhResponse<WorkflowResponse>> {
    return this.request<WorkflowResponse>(
      `/repos/${this.owner}/${this.repo}/actions/workflows?per_page=100`,
    );
  }

  async actionPermissions(): Promise<GhResponse<ActionsPermissions>> {
    return this.request<ActionsPermissions>(
      `/repos/${this.owner}/${this.repo}/actions/permissions`,
    );
  }

  /**
   * Recent workflow runs. This is what distinguishes a control that is configured
   * from one that is operating: a required check nobody has run proves nothing.
   */
  async actionRuns(
    perPage = 50,
  ): Promise<GhResponse<ActionRunsResponse>> {
    return this.request<ActionRunsResponse>(
      `/repos/${this.owner}/${this.repo}/actions/runs?per_page=${perPage}`,
    );
  }

  /**
   * GitHub Environments. Each may carry required reviewers, which is the
   * closest verifiable analogue of privileged-access approval for a repository.
   */
  async environments(): Promise<GhResponse<EnvironmentResponse>> {
    return this.request<EnvironmentResponse>(
      `/repos/${this.owner}/${this.repo}/environments?per_page=100`,
    );
  }

  async closedPulls(
    perPage = 30,
  ): Promise<GhResponse<PullResponse[]>> {
    return this.request<PullResponse[]>(
      `/repos/${this.owner}/${this.repo}/pulls?state=closed&per_page=${perPage}&sort=updated&direction=desc`,
    );
  }

  async pullReviews(
    number: number,
  ): Promise<GhResponse<ReviewResponse[]>> {
    return this.request<ReviewResponse[]>(
      `/repos/${this.owner}/${this.repo}/pulls/${number}/reviews?per_page=100`,
    );
  }

  async releases(): Promise<GhResponse<unknown[]>> {
    return this.request<unknown[]>(
      `/repos/${this.owner}/${this.repo}/releases?per_page=30`,
    );
  }

  /** Issues and PRs, used as an incident-response record. */
  async closedIssues(
    perPage = 50,
  ): Promise<GhResponse<IssueResponse[]>> {
    return this.request<IssueResponse[]>(
      `/repos/${this.owner}/${this.repo}/issues?state=closed&per_page=${perPage}&sort=updated&direction=desc`,
    );
  }

  async tags(): Promise<GhResponse<{ name: string }[]>> {
    return this.request<{ name: string }[]>(
      `/repos/${this.owner}/${this.repo}/tags?per_page=30`,
    );
  }

  /**
   * The full recursive tree for a ref, in one request. Most file-presence checks
   * in auditgen are answered from this, which keeps a full audit inside a
   * handful of API calls rather than dozens.
   */
  async treeRecursive(branch: string): Promise<GhResponse<TreeResponse>> {
    return this.request<TreeResponse>(
      `/repos/${this.owner}/${this.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    );
  }

  /** Raw blob by sha, decoded to text. */
  async blob(sha: string): Promise<GhResponse<string>> {
    const res = await this.request<BlobResponse>(
      `/repos/${this.owner}/${this.repo}/git/blobs/${sha}`,
    );
    if (!res.ok || !res.data) return { ok: false, status: res.status, reason: res.reason };
    if (res.data.encoding === "base64" && res.data.content) {
      return {
        ok: true,
        status: res.status,
        data: Buffer.from(res.data.content, "base64").toString("utf8"),
      };
    }
    return { ok: false, status: res.status, reason: "unexpected encoding" };
  }
}

// ---- Response shapes (only the fields auditgen reads) ----------------------

export interface RepoResponse {
  full_name: string;
  private: boolean;
  archived: boolean;
  disabled: boolean;
  default_branch: string;
  visibility?: string;
  description?: string | null;
  homepage?: string | null;
  created_at: string;
  pushed_at: string;
  open_issues_count: number;
  forks_count: number;
  stargazers_count: number;
  license?: { spdx_id: string | null; name: string } | null;
  security_and_analysis?: {
    advanced_security?: { status: string };
    secret_scanning?: { status: string };
    secret_scanning_push_protection?: { status: string };
    secret_scanning_validity_checks?: { status: string };
  } | null;
  owner?: { login: string; type: string };
}

export interface ContentResponse {
  type: string;
  name: string;
  path: string;
  sha: string;
  size: number;
  encoding?: string;
  content?: string;
  download_url?: string | null;
}

export interface BranchProtection {
  url?: string;
  required_status_checks?: {
    strict: boolean;
    contexts: string[] | null;
  } | null;
  enforce_admins?: { enabled: boolean } | null;
  required_pull_request_reviews?: {
    dismiss_stale_reviews?: boolean;
    require_code_owner_reviews?: boolean;
    required_approving_review_count?: number;
    require_last_push_approval?: boolean;
  } | null;
  restrictions?: { users: unknown[]; teams: unknown[]; apps: unknown[] } | null;
  required_linear_history?: { enabled: boolean } | null;
  allow_force_pushes?: { enabled: boolean } | null;
  allow_deletions?: { enabled: boolean } | null;
  required_conversation_resolution?: { enabled: boolean } | null;
}

export interface WorkflowResponse {
  total_count: number;
  workflows: {
    id: number;
    name: string;
    path: string;
    state: string;
  }[];
}

export interface ActionsPermissions {
  enabled: boolean;
  allowed_actions: string;
  sha_pinning_required?: boolean | null;
}

export interface PullResponse {
  number: number;
  title: string;
  merged_at: string | null;
  user?: { login: string };
  additions: number;
  deletions: number;
  changed_files: number;
  labels: { name: string }[];
}

export interface ReviewResponse {
  state: string;
  submitted_at: string | null;
  user?: { login: string };
}

export interface IssueResponse {
  number: number;
  title: string;
  closed_at: string | null;
  labels: { name: string }[];
  is_pr?: boolean;
}

export interface ActionRunsResponse {
  total_count: number;
  workflow_runs: {
    id: number;
    name: string;
    event: string;
    status: string;
    conclusion: string | null;
    path: string;
    head_branch: string;
    created_at: string;
    updated_at: string;
    run_number: number;
  }[];
}

export interface EnvironmentResponse {
  total_count: number;
  environments: {
    id: number;
    name: string;
    protection_rules: {
      id: number;
      type: string;
      reviewers?: { type: string; reviewer?: { login?: string } }[];
    }[];
    deployment_branch_policy?: { protected_branches: boolean } | null;
  }[];
}

export interface TreeResponse {
  sha: string;
  truncated: boolean;
  tree: {
    path: string;
    mode: string;
    type: "blob" | "tree" | "commit";
    sha: string;
    size?: number;
    url?: string;
  }[];
}

export interface BlobResponse {
  sha: string;
  size: number;
  encoding: string;
  content: string;
}

/** Resolves a token from an explicit value or the usual environment variables. */
export function resolveToken(explicit?: string): string | undefined {
  if (explicit) return explicit;
  for (const key of ["AUDITGEN_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]) {
    const v = process.env[key];
    if (v && v.trim()) return v.trim();
  }
  return undefined;
}

/** Reads a file's text content out of a contents-API response. */
export function decodeContent(data: ContentResponse): string | undefined {
  if (data.type !== "file") return undefined;
  if (data.content && data.encoding === "base64") {
    return Buffer.from(data.content, "base64").toString("utf8");
  }
  return undefined;
}