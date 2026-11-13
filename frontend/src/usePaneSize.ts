import { RefObject, useEffect, useLayoutEffect, useState } from 'react';

const useMeasuredLayout = typeof window === 'undefined' ? useEffect : useLayoutEffect;

/** Measure the container rather than the viewport so zoom and split resizing agree. */
export function usePaneSize(ref: RefObject<HTMLElement>, dimension: 'width' | 'height', initial: number) {
  const [size, setSize] = useState(initial);
  useMeasuredLayout(() => {
    const element = ref.current;
    if (!element) return;
    const measure = () => setSize(element.getBoundingClientRect()[dimension]);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref, dimension]);
  return size;
}
