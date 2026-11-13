/** Coalesce split-pane resize notifications into one canvas update per frame. */
export function observeGraphResize(element: HTMLElement, graph: { resize: () => unknown; fit: (elements?: undefined, padding?: number) => unknown }) {
  let frame = 0;
  const observer = new ResizeObserver(() => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      graph.resize();
      graph.fit(undefined, 25);
      frame = 0;
    });
  });
  observer.observe(element);
  return () => { observer.disconnect(); cancelAnimationFrame(frame); };
}
