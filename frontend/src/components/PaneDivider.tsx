import React, { useEffect, useRef, useState } from 'react';
import { startPaneDrag } from '../splitLayout';

interface Props {
  orientation: 'vertical' | 'horizontal';
  label: string;
  controls: string;
  value: number;
  min: number;
  max: number;
  onDelta: (delta: number) => void;
  onReset: () => void;
}

export function PaneDivider({ orientation, label, controls, value, min, max, onDelta, onReset }: Props) {
  const cleanup = useRef<(() => void) | null>(null);
  const [dragging, setDragging] = useState(false);
  useEffect(() => () => cleanup.current?.(), []);
  return <div role="separator" tabIndex={0} aria-label={label} aria-orientation={orientation}
    aria-controls={controls} aria-valuenow={Math.round(value)} aria-valuemin={Math.round(min)} aria-valuemax={Math.round(max)}
    aria-valuetext={`${Math.round(value)} pixels`} title={`${label} · kéo để đổi kích thước · phím mũi tên · nhấp đúp để khôi phục`}
    className={`pane-divider pane-divider-${orientation}`} data-dragging={dragging || undefined}
    onDoubleClick={onReset}
    onPointerDown={event => {
      if (event.button !== 0 || !event.isPrimary) return;
      cleanup.current?.();
      setDragging(true);
      cleanup.current = startPaneDrag(event.currentTarget, event.nativeEvent, orientation, onDelta, () => setDragging(false));
    }}
    onKeyDown={event => {
      const negative = orientation === 'vertical' ? 'ArrowLeft' : 'ArrowUp';
      const positive = orientation === 'vertical' ? 'ArrowRight' : 'ArrowDown';
      const delta = event.key === negative ? -24 : event.key === positive ? 24 :
        event.key === 'Home' ? min - value : event.key === 'End' ? max - value : null;
      if (delta !== null) { event.preventDefault(); onDelta(delta); }
    }}><span aria-hidden="true" /></div>;
}
