import React, { useState, useRef } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, Download } from 'lucide-react';

interface InteractiveSvgCanvasProps {
  title: string;
  subtitle: string;
  svgMarkup: string;
  filenameSlug?: string;
  minHeight?: string;
  onStateHover?: (info: { kind: 'NFA' | 'POW' | 'MIN'; id: number } | null) => void;
}

export const InteractiveSvgCanvas: React.FC<InteractiveSvgCanvasProps> = ({
  title,
  subtitle,
  svgMarkup,
  filenameSlug = 'automaton',
  minHeight = 'h-[310px]',
  onStateHover,
}) => {
  const [scale, setScale] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  const handleWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.15 : 0.87;
    setScale((s) => Math.min(5.0, Math.max(0.2, +(s * factor).toFixed(2))));
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y,
      });
    }

    if (!onStateHover) return;
    const target = e.target as HTMLElement;
    const nfaGroup = target.closest?.('[data-nfa-id]') as HTMLElement | null;
    if (nfaGroup) {
      const id = parseInt(nfaGroup.getAttribute('data-nfa-id') || '0', 10);
      onStateHover({ kind: 'NFA', id });
      return;
    }
    const dfaGroup = target.closest?.('[data-dfa-id]') as HTMLElement | null;
    if (dfaGroup) {
      const id = parseInt(dfaGroup.getAttribute('data-dfa-id') || '0', 10);
      const kindAttr = dfaGroup.getAttribute('data-dfa-kind');
      onStateHover({ kind: kindAttr === 'MINIMAL' ? 'MIN' : 'POW', id });
      return;
    }
    onStateHover(null);
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleMouseLeave = () => {
    setIsDragging(false);
    if (onStateHover) onStateHover(null);
  };

  const handleDownloadSvg = () => {
    const blob = new Blob([svgMarkup], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filenameSlug}.svg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col border border-slate-800 bg-slate-900/90 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between gap-4 px-4 py-2.5 border-b border-slate-800 bg-slate-950/60">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100 truncate">{title}</h3>
          <p className="text-xs text-slate-400 font-mono truncate">{subtitle}</p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => setScale((s) => Math.min(2.6, +(s + 0.2).toFixed(2)))}
            title="Zoom in"
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => setScale((s) => Math.max(0.5, +(s - 0.2).toFixed(2)))}
            title="Zoom out"
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              setScale(1);
              setPan({ x: 0, y: 0 });
            }}
            title="Reset view"
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={handleDownloadSvg}
            title="Download vector SVG"
            className="p-1.5 text-slate-400 hover:text-sky-300 hover:bg-slate-800 rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        onWheel={handleWheel}
        className={`relative w-full ${minHeight} studio-grid-bg overflow-hidden cursor-grab active:cursor-grabbing flex items-center justify-center p-4`}
      >
        <div
          style={{
            transform: `translate3d(${pan.x}px, ${pan.y}px, 0) scale(${scale})`,
            transformOrigin: 'center center',
          }}
          className="w-full h-full flex items-center justify-center transition-transform duration-75"
          dangerouslySetInnerHTML={{ __html: svgMarkup }}
        />
      </div>
    </div>
  );
};
