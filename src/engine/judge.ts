import type { Control, Finding } from "../types.js";

/**
 * Narrative pass.
 *
 * Deliberately narrow: this module can only write prose. It cannot set a
 * status, promote a control, or remove a gap. Status is computed from
 * deterministic repository observation in evaluate.ts, and stays that way
 * regardless of which model is configured. An auditor's worst fear about
 * "AI-generated compliance evidence" is a model deciding it is compliant.
 */

export interface JudgeOptions {
  baseUrl?: string;
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
}

export interface JudgeResult {
  applied: number;
  model?: string;
  error?: string;
  skippedReason?: string;
}

/** Providers whose default model we are confident about. */
function defaultModelFor(baseUrl: string): string | undefined {
  if (/api\.openai\.com/i.test(baseUrl)) return "gpt-4o-mini";
  return undefined;
}

export function resolveJudgeConfig(
  explicit?: JudgeOptions,
): { baseUrl: string; apiKey?: string; model: string } | { error: string } {
  const baseUrl =
    explicit?.baseUrl ??
    process.env.AUDITGEN_AI_BASE_URL ??
    process.env.OPENAI_BASE_URL ??
    process.env.OPENROUTER_BASE_URL;
  const apiKey =
    explicit?.apiKey ??
    process.env.AUDITGEN_AI_API_KEY ??
    process.env.OPENAI_API_KEY ??
    process.env.OPENROUTER_API_KEY ??
    process.env.GROQ_API_KEY ??
    process.env.DEEPSEEK_API_KEY;
  const model =
    explicit?.model ?? process.env.AUDITGEN_AI_MODEL ?? (baseUrl ? defaultModelFor(baseUrl) : undefined);

  if (!baseUrl) {
    return {
      error:
        "No AI endpoint configured. Set AUDITGEN_AI_BASE_URL (and AUDITGEN_AI_API_KEY unless running a local server) to enable narrative generation, or pass --no-ai.",
    };
  }
  if (!model) {
    return {
      error: `AUDITGEN_AI_MODEL is not set and no default is known for ${baseUrl}. Set it explicitly, for example AUDITGEN_AI_MODEL=<model-id>.`,
    };
  }
  return { baseUrl: baseUrl.replace(/\/+$/, ""), ...(apiKey ? { apiKey } : {}), model };
}

/** Only findings that need prose work are sent. */
function needsNarrative(f: Finding): boolean {
  return f.status !== "satisfied";
}

function controlPayload(c: Control): Record<string, unknown> {
  return {
    id: c.id,
    title: c.title,
    requirement: c.requirement,
    category: c.category,
    guidance: c.guidance,
  };
}

const SYSTEM_PROMPT = `You write narrative text for a SOC 2 / ISO 27001 compliance report produced by auditgen.

You will receive the audit findings for controls that are not fully satisfied. For each one, return:
- "narrative": one short paragraph, plain prose, addressed to an auditor explaining what was observed and what it means for this control. State facts only. Do not speculate about intent, and do not claim a control is satisfied. Two to four sentences.
- "remediation": an ordered array of concrete steps to close the gap. Each step must be actionable by a software engineer and specific to what was actually observed. No generic advice such as "improve security". Two to five steps.

Hard rules:
- Never contradict the supplied status. The status is computed deterministically from repository observation and is not yours to change.
- Never invent evidence, findings, or systems that were not supplied to you.
- Never claim a control is compliant, certified, or passing.
- Prefer concrete nouns and identifiers over adjectives.

Return only a JSON object keyed by control id.`;

export async function enrichFindings(
  findings: Finding[],
  options?: JudgeOptions,
): Promise<JudgeResult> {
  const targets = findings.filter(needsNarrative);
  if (targets.length === 0) return { applied: 0 };

  const resolved = resolveJudgeConfig(options);
  if ("error" in resolved) {
    return { applied: 0, skippedReason: resolved.error };
  }

  const payload = targets.map((f) => ({
    ...controlPayload(f.control),
    status: f.status,
    evidenceStrength: f.score,
    observations: f.evidence.map((e) => ({
      assertion: e.title,
      passed: e.passed,
      details: e.details,
    })),
    knownGaps: f.gaps,
  }));

  const url = `${resolved.baseUrl}/chat/completions`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (resolved.apiKey) headers.Authorization = `Bearer ${resolved.apiKey}`;

  const body = {
    model: resolved.model,
    temperature: 0.1,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: JSON.stringify({ findings: payload }, null, 2),
      },
    ],
    response_format: { type: "json_object" },
  };

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    options?.timeoutMs ?? 90_000,
  );

  let text: string;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      return {
        applied: 0,
        model: resolved.model,
        error: `AI endpoint returned HTTP ${res.status}. ${detail.slice(0, 300)}`,
      };
    }
    const json = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    text = json.choices?.[0]?.message?.content ?? "";
  } catch (err) {
    return {
      applied: 0,
      model: resolved.model,
      error: `AI endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    clearTimeout(timer);
  }

  let parsed: Record<string, { narrative?: string; remediation?: unknown }>;
  try {
    parsed = JSON.parse(extractJsonObject(text)) as typeof parsed;
  } catch {
    return {
      applied: 0,
      model: resolved.model,
      error: "AI endpoint returned a response that was not valid JSON.",
    };
  }

  let applied = 0;
  for (const finding of targets) {
    const entry = parsed[finding.control.id];
    if (!entry) continue;

    if (typeof entry.narrative === "string" && entry.narrative.trim()) {
      finding.rationale = entry.narrative.trim();
      finding.aiGenerated = true;
      applied++;
    }

    if (Array.isArray(entry.remediation)) {
      const steps = entry.remediation
        .filter((s): s is string => typeof s === "string")
        .map((s) => s.trim())
        .filter(Boolean);
      if (steps.length > 0) {
        // The model's remediation is advisory: the deterministic gaps stay in the
        // report so the operator can see what the tool actually detected.
        finding.remediation = steps;
        finding.aiGenerated = true;
      }
    }
  }

  return { applied, model: resolved.model };
}

/** Tolerates models that wrap JSON in prose or fences. */
export function extractJsonObject(text: string): string {
  const trimmed = text.trim();
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed);
  if (fenced?.[1]) return fenced[1].trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start !== -1 && end > start) return trimmed.slice(start, end + 1);
  return trimmed;
}