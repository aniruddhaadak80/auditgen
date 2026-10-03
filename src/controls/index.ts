import type { Control, Framework } from "../types.js";
import { SOC2_CONTROLS } from "./soc2.js";
import { ISO27001_CONTROLS } from "./iso27001.js";

export { SOC2_CONTROLS } from "./soc2.js";
export { ISO27001_CONTROLS } from "./iso27001.js";

export const ALL_CONTROLS: Control[] = [...SOC2_CONTROLS, ...ISO27001_CONTROLS];

const BY_ID = new Map<string, Control>(ALL_CONTROLS.map((c) => [c.id, c]));

export function getControl(id: string): Control | undefined {
  return BY_ID.get(id);
}

export function controlsFor(frameworks: Framework[]): Control[] {
  return ALL_CONTROLS.filter((c) => frameworks.includes(c.framework));
}

/** Every distinct collector referenced by the given controls. */
export function collectorsNeeded(controls: Control[]): string[] {
  return [...new Set(controls.map((c) => c.collector))];
}

export function listCollectorNames(): string[] {
  return collectorsNeeded(ALL_CONTROLS);
}