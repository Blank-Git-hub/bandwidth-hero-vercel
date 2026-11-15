let count = 0;

export function enter() { count++; }
export function leave() { count = Math.max(0, count - 1); }
export function current() { return count; }

export default { enter, leave, current };
