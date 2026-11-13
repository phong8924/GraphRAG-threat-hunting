export const DIVIDER_SIZE = 8;
export const COLUMN_MINIMUMS = [220, 280, 320];
export const DEFAULT_COLUMNS = [3 / 12, 5 / 12, 4 / 12];
export const DEFAULT_SETTINGS_RATIO = 0.4;
export const MIN_SETTINGS_HEIGHT = 88;
export const MIN_ANSWER_HEIGHT = 120;
export const MIN_LAYOUT_WIDTH = COLUMN_MINIMUMS.reduce((a, b) => a + b, 0) + 2 * DIVIDER_SIZE;

export const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

/** Distribute actual available pixels, respecting every pane's minimum. */
export function columnPixels(ratios: number[], available: number): number[] {
  const total = Math.max(available, MIN_LAYOUT_WIDTH - 2 * DIVIDER_SIZE);
  const sizes = [0, 0, 0];
  let remaining = total;
  let active = [0, 1, 2];
  while (active.length) {
    const weight = active.reduce((sum, i) => sum + ratios[i], 0);
    const limited = active.filter(i => remaining * ratios[i] / weight < COLUMN_MINIMUMS[i]);
    if (!limited.length) {
      active.forEach(i => { sizes[i] = remaining * ratios[i] / weight; });
      break;
    }
    limited.forEach(i => { sizes[i] = COLUMN_MINIMUMS[i]; remaining -= sizes[i]; });
    active = active.filter(i => !limited.includes(i));
  }
  return sizes;
}

/** A divider moves only its two adjacent panes; the third pane stays fixed. */
export function resizeColumns(start: number[], divider: number, delta: number): number[] {
  const sizes = [...start];
  const movement = clamp(delta, COLUMN_MINIMUMS[divider] - sizes[divider], sizes[divider + 1] - COLUMN_MINIMUMS[divider + 1]);
  sizes[divider] += movement;
  sizes[divider + 1] -= movement;
  const total = sizes.reduce((a, b) => a + b, 0);
  return sizes.map(size => size / total);
}

export function settingsPixels(ratio: number, available: number): number {
  const total = Math.max(available, MIN_SETTINGS_HEIGHT + MIN_ANSWER_HEIGHT);
  return clamp(ratio * total, MIN_SETTINGS_HEIGHT, total - MIN_ANSWER_HEIGHT);
}

/** Pointer capture + window listeners keep dragging outside the narrow handle reliable. */
export function startPaneDrag(handle: HTMLElement, event: PointerEvent, orientation: 'vertical' | 'horizontal',
  onDelta: (delta: number) => void, onEnd: () => void): () => void {
  if (event.button !== 0 || event.isPrimary === false) return () => {};
  event.preventDefault();
  const doc = handle.ownerDocument;
  const view = doc.defaultView!;
  const root = doc.documentElement;
  const previousCursor = root.style.cursor;
  const previousSelection = root.style.userSelect;
  const coordinate = (e: PointerEvent) => orientation === 'vertical' ? e.clientX : e.clientY;
  const origin = coordinate(event);
  let ended = false;
  const move = (e: PointerEvent) => {
    if (e.pointerId !== event.pointerId) return;
    e.preventDefault();
    onDelta(coordinate(e) - origin);
  };
  const finish = () => {
    if (ended) return;
    ended = true;
    view.removeEventListener('pointermove', move);
    view.removeEventListener('pointerup', up);
    view.removeEventListener('pointercancel', cancel);
    view.removeEventListener('blur', finish);
    view.removeEventListener('keydown', key);
    handle.removeEventListener('lostpointercapture', cancel);
    if (handle.hasPointerCapture(event.pointerId)) handle.releasePointerCapture(event.pointerId);
    root.classList.remove('resizing-panes');
    root.style.cursor = previousCursor;
    root.style.userSelect = previousSelection;
    onEnd();
  };
  const up = (e: PointerEvent) => { if (e.pointerId === event.pointerId) { move(e); finish(); } };
  const cancel = (e: PointerEvent) => { if (e.pointerId === event.pointerId) finish(); };
  const key = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.preventDefault(); finish(); } };
  handle.setPointerCapture(event.pointerId);
  root.classList.add('resizing-panes');
  root.style.cursor = orientation === 'vertical' ? 'col-resize' : 'row-resize';
  root.style.userSelect = 'none';
  view.addEventListener('pointermove', move, { passive: false });
  view.addEventListener('pointerup', up);
  view.addEventListener('pointercancel', cancel);
  view.addEventListener('blur', finish);
  view.addEventListener('keydown', key);
  handle.addEventListener('lostpointercapture', cancel);
  return finish;
}
