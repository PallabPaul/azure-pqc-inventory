/**
 * Minimal ANSI color helper. Honours NO_COLOR, FORCE_COLOR, and whether stdout
 * is a TTY. Call `setColorEnabled(false)` to force-disable (e.g. `--no-color`).
 */

let enabled =
  process.env.NO_COLOR === undefined &&
  (process.env.FORCE_COLOR !== undefined || process.stdout.isTTY === true);

export function setColorEnabled(value: boolean): void {
  enabled = value;
}

function wrap(open: number, close: number): (s: string) => string {
  return (s: string) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : s);
}

export const color = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  cyan: wrap(36, 39),
};
