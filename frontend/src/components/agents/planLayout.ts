/**
 * Pure helpers for the multi-agent plan shown in the chat page.
 * No React and no DOM here, so the logic can be checked on its own.
 */

export type PlanStepState = "waiting" | "running" | "done" | "failed";

export interface PlanStep {
  number: number;
  description: string;
  agentId: string;
  agentName: string;
  dependsOn: number[];
  state: PlanStepState;
}

export interface PlanEdge {
  from: number;
  to: number;
}

export interface PlanLayout {
  /** "layered": columns by dependency depth. "list": the data cannot be drawn as a graph. */
  kind: "layered" | "list";
  /** Step numbers per column, column 0 first. Empty for "list". */
  layers: number[][];
  /** One edge per dependency, from the earlier step to the step that depends on it. Empty for "list". */
  edges: PlanEdge[];
  /** Step numbers in reading order: column by column for "layered", input order for "list". */
  order: number[];
}

/**
 * Arrange plan steps in columns by dependency depth.
 *
 * A step with no dependencies is in column 0. Any other step is one column to
 * the right of its deepest dependency. Inside a column, steps keep input order.
 *
 * The result is "list" (input order, no columns, no edges) when the data is
 * not a graph that can be layered: a cycle, a step that depends on itself, a
 * dependency on a step that is not in the plan, or two steps with the same
 * number. The loop below removes at least one step per pass or stops, so it
 * always ends.
 *
 * Examples (number: dependsOn  ->  layers, edges):
 *   single step     1:[]                          -> [[1]], no edges
 *   linear chain    1:[] 2:[1] 3:[2]              -> [[1],[2],[3]], 1>2 2>3
 *   fan-out/fan-in  1:[] 2:[1] 3:[1] 4:[2,3]      -> [[1],[2,3],[4]], 1>2 1>3 2>4 3>4
 *   uneven depth    1:[] 2:[] 3:[1] 4:[2,3]       -> [[1,2],[3],[4]], 1>3 2>4 3>4
 *   repeated dep    1:[] 2:[1,1]                  -> [[1],[2]], 1>2 (once)
 *   cycle           1:[] 2:[3] 3:[2]              -> kind "list", order [1,2,3]
 *   self reference  1:[1]                         -> kind "list", order [1]
 *   unknown step    1:[] 2:[7]                    -> kind "list", order [1,2]
 *   duplicate ids   1:[] 1:[]                     -> kind "list", order [1,1]
 *   empty           (no steps)                    -> kind "list", order []
 */
export function layoutPlan(steps: ReadonlyArray<Pick<PlanStep, "number" | "dependsOn">>): PlanLayout {
  const order = steps.map((s) => s.number);
  const asList: PlanLayout = { kind: "list", layers: [], edges: [], order };

  const known = new Set(order);
  if (steps.length === 0 || known.size !== steps.length) return asList;

  const deps = new Map<number, number[]>();
  for (const step of steps) {
    const unique = Array.from(new Set(step.dependsOn));
    if (unique.some((d) => d === step.number || !known.has(d))) return asList;
    deps.set(step.number, unique);
  }

  const depth = new Map<number, number>();
  let remaining = steps.map((s) => s.number);
  while (remaining.length > 0) {
    const ready = remaining.filter((n) => (deps.get(n) ?? []).every((d) => depth.has(d)));
    if (ready.length === 0) return asList; // cycle
    // Depths are assigned after the filter so every step in one pass only sees earlier passes.
    const placed = ready.map((n) => {
      const parents = deps.get(n) ?? [];
      return [n, parents.length ? Math.max(...parents.map((d) => depth.get(d) ?? 0)) + 1 : 0] as const;
    });
    for (const [n, d] of placed) depth.set(n, d);
    const done = new Set(ready);
    remaining = remaining.filter((n) => !done.has(n));
  }

  const layers: number[][] = [];
  for (const n of order) {
    const d = depth.get(n) ?? 0;
    (layers[d] ??= []).push(n);
  }
  const edges: PlanEdge[] = [];
  for (const n of order) for (const d of deps.get(n) ?? []) edges.push({ from: d, to: n });

  return { kind: "layered", layers, edges, order: layers.flat() };
}

const asText = (value: unknown): string => (typeof value === "string" ? value : "");

const asNumbers = (value: unknown): number[] =>
  Array.isArray(value) ? value.map(Number).filter((n) => Number.isFinite(n)) : [];

/** Agent ids look like "security_analyst"; show "Security analyst" when the server sent no name. */
export function agentLabel(name: unknown, id: unknown): string {
  const given = asText(name).trim();
  if (given) return given;
  const fallback = asText(id).replace(/[_-]+/g, " ").trim();
  return fallback ? fallback.charAt(0).toUpperCase() + fallback.slice(1) : "Agent";
}

/**
 * Read the steps of a `plan` stream event. The server sends
 * `{step, description, agent, agent_name, depends_on, status}` per step.
 * Entries without a usable step number are dropped; nothing is invented.
 */
export function parsePlanSteps(raw: unknown): PlanStep[] {
  if (!Array.isArray(raw)) return [];
  const steps: PlanStep[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const item = entry as Record<string, unknown>;
    const number = Number(item.step ?? item.number);
    if (!Number.isFinite(number)) continue;
    const status = asText(item.status);
    steps.push({
      number,
      description: asText(item.description),
      agentId: asText(item.agent ?? item.agent_id),
      agentName: agentLabel(item.agent_name, item.agent ?? item.agent_id),
      dependsOn: asNumbers(item.depends_on ?? item.dependsOn),
      state: status === "running" ? "running" : status === "done" ? "done" : status === "failed" ? "failed" : "waiting",
    });
  }
  return steps;
}

/**
 * Apply an `agent_spawn` (state "running") or `agent_complete` (state "done" or
 * "failed") event to the plan. The event's step number decides which step
 * changes. Without one, the first step of that agent still in the previous
 * state changes, so an agent used in two steps is not marked twice.
 */
export function applyStepState(
  steps: PlanStep[],
  event: { step?: unknown; agentId?: unknown },
  state: Exclude<PlanStepState, "waiting">,
): PlanStep[] {
  const stepNumber = typeof event.step === "number" ? event.step : null;
  let index = stepNumber === null ? -1 : steps.findIndex((s) => s.number === stepNumber);
  if (index < 0 && stepNumber === null) {
    const agentId = asText(event.agentId);
    const previous: PlanStepState = state === "running" ? "waiting" : "running";
    index = agentId ? steps.findIndex((s) => s.agentId === agentId && s.state === previous) : -1;
  }
  if (index < 0 || steps[index].state === state) return steps;
  return steps.map((s, i) => (i === index ? { ...s, state } : s));
}

/** "Plan: 4 steps, 3 done" (and ", 1 failed" when there are failures). */
export function planSummary(steps: ReadonlyArray<Pick<PlanStep, "state">>): string {
  const done = steps.filter((s) => s.state === "done").length;
  const failed = steps.filter((s) => s.state === "failed").length;
  const total = `${steps.length} ${steps.length === 1 ? "step" : "steps"}`;
  return `Plan: ${total}, ${done} done${failed ? `, ${failed} failed` : ""}`;
}
