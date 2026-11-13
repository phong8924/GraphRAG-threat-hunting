import React, { useState, useEffect, useMemo, useRef } from 'react';
import { CytoscapeGraph } from './components/CytoscapeGraph';
import { ChatPanel } from './components/ChatPanel';
import { EvidenceSidebar } from './components/EvidenceSidebar';
import { PaneDivider } from './components/PaneDivider';
import { COLUMN_MINIMUMS, DEFAULT_COLUMNS, DEFAULT_SETTINGS_RATIO, DIVIDER_SIZE, MIN_LAYOUT_WIDTH, columnPixels, resizeColumns } from './splitLayout';
import { usePaneSize } from './usePaneSize';
import { CyberGraphShieldIcon, SunIcon, MoonIcon, RefreshIcon } from './components/SvgIcons';
import { CytoscapeElement, EvidenceItem, HuntResponse, ScenarioInfo } from './types';
import { ExperimentalResponse } from './experimentalState';
import { loadSavedLiveResult } from './savedLiveResult';
import { assertCurrentRequest, experimentalApi, ExperimentalBranch, ExperimentalConfiguration,
  ExperimentalPreset, experimentalGraph, initialOfflineDemo, runExperimental, selectArtifactProfile } from './experimentalDashboard';

export const App: React.FC = () => {
  const [savedView, setSavedView] = useState(() => typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('view') === 'saved-mshta');
  const [columns, setColumns] = useState(DEFAULT_COLUMNS);
  const [settingsRatio, setSettingsRatio] = useState(DEFAULT_SETTINGS_RATIO);
  const splitRef = useRef<HTMLElement>(null);
  const splitWidth = usePaneSize(splitRef, 'width', 1200);
  const widths = columnPixels(columns, splitWidth - 2 * DIVIDER_SIZE);
  const resetLayout = () => { setColumns(DEFAULT_COLUMNS); setSettingsRatio(DEFAULT_SETTINGS_RATIO); };
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('soc_theme') as 'dark' | 'light') || 'dark';
  });

  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('mshta-powershell');
  const [graphElements, setGraphElements] = useState<CytoscapeElement[]>([]);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [mode, setMode] = useState<'legacy' | 'experimental'>('experimental');
  const [branch, setBranch] = useState<ExperimentalBranch>('rag');
  const [configuration, setConfiguration] = useState<ExperimentalConfiguration | null>(null);
  const [experimentalResponse, setExperimentalResponse] = useState<ExperimentalResponse | null>(null);
  const [experimentalQuery, setExperimentalQuery] = useState('');
  const [liveEnabled, setLiveEnabled] = useState(false);
  const epoch = useRef(0);
  const inFlight = useRef(false);
  const autoDemoStarted = useRef(false);
  const sourceReviewMode = mode === 'experimental' && configuration?.runtime_mode === 'offline_source_review' &&
    configuration.mode === 'experimental_offline_demo' && configuration.generation_disabled === true && configuration.maximum_llm_requests === 0;
  const displayedGraph = useMemo(() => mode === 'experimental' ? experimentalGraph(experimentalResponse) : graphElements,
    [mode, experimentalResponse, graphElements]);

  const clearResult = () => {
    epoch.current += 1;
    setExperimentalResponse(null); setGraphElements([]); setEvidenceItems([]);
    setSelectedNode(null); setErrorMessage(null);
  };
  const selectScenario = (value: string) => {
    const preset = sourceReviewMode ? configuration?.presets.find(p => p.scenario_id === value) : null;
    if (preset) { void loadDemo(preset); return; }
    clearResult(); setSelectedScenario(value);
  };
  const selectMode = (value: 'legacy' | 'experimental') => {
    clearResult(); setLiveEnabled(false); setMode(value);
  };

  // Sync theme attribute
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('soc_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const showSavedResult = async (config = configuration) => {
    if (!config || inFlight.current) return;
    const token = ++epoch.current;
    setIsLoading(true); setLiveEnabled(false); setErrorMessage(null);
    try {
      const response = await loadSavedLiveResult(config);
      if (token !== epoch.current || !response) return;
      setSavedView(true); setSelectedScenario(response.request.scenario_id); setBranch(response.request.branch as ExperimentalBranch);
      setExperimentalQuery(response.request.query); setExperimentalResponse({ ...response, display_compact: true });
      setSettingsRatio(0.05); setColumns([0.25, 0.27, 0.48]);
      if (typeof window !== 'undefined') window.history.replaceState(null, '', '?view=saved-mshta');
    } catch (err) { if (token === epoch.current) setErrorMessage(String(err)); }
    finally { setIsLoading(false); }
  };

  // Isolate both modes: experimental never loads whole-scenario production evidence/graphs.
  useEffect(() => {
    let active = true;
    if (mode === 'experimental') {
      experimentalApi<ExperimentalConfiguration>('config')
        .then(data => {
          if (!active) return;
          setConfiguration(data);
          if (savedView && data.current_source_profile) { void showSavedResult(data); return; }
          if (data.current_source_profile && data.load_latest_on_open) {
            const token = epoch.current;
            const first = data.presets.find(p => p.scenario_id === 'mshta-powershell');
            if (first) { setExperimentalQuery(first.query); setSelectedScenario(first.scenario_id); }
            void experimentalApi<ExperimentalResponse | null>('recent').then(async current => {
              const response = current ? { ...current, display_origin: 'current_session' as const } : await loadSavedLiveResult(data);
              if (!active || token !== epoch.current || !response) return;
              setSelectedScenario(response.request.scenario_id);
              setBranch(response.request.branch as ExperimentalBranch);
              setExperimentalQuery(response.request.query);
              setExperimentalResponse(response);
              if (current) setConfiguration(previous => previous ? { ...previous, ...response.configuration } : previous);
            }).catch(err => { if (active && token === epoch.current) setErrorMessage(String(err)); });
          }
          const preset = initialOfflineDemo(data);
          if (preset && !autoDemoStarted.current && epoch.current === 0) {
            autoDemoStarted.current = true;
            setSettingsRatio(0.34);
            void loadDemo(preset, data);
          }
        })
        .catch(err => { if (active) setErrorMessage(String(err)); });
      return () => { active = false; };
    }
    fetch('/api/scenarios')
      .then((res) => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
      .then((data) => {
        if (active && Array.isArray(data) && data.length > 0) {
          setScenarios(data);
          setSelectedScenario(data[0].scenario_id);
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err);
        if (active) setErrorMessage('Không tải được kịch bản. Kiểm tra backend và artifacts bằng scripts/check_installation.py.');
      });
    return () => { active = false; };
  }, [mode]);

  // 2. Fetch full graph and evidence when scenario changes
  const loadScenarioData = (scenId: string) => {
    if (mode !== 'legacy') return;
    const token = epoch.current;
    setSelectedNode(null);
    setErrorMessage(null);

    fetch(`/api/graph?scenario_id=${scenId}`)
      .then((res) => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
      .then((data) => {
        if (token === epoch.current && data.elements) {
          setGraphElements(data.elements);
        }
      })
      .catch((err) => { if (token === epoch.current) setErrorMessage(`Không tải được đồ thị: ${err.message}`); });

    fetch(`/api/evidence?scenario_id=${scenId}`)
      .then((res) => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); })
      .then((data) => {
        if (token === epoch.current && data.evidence_items) {
          setEvidenceItems(data.evidence_items);
        }
      })
      .catch((err) => { if (token === epoch.current) setErrorMessage(`Không tải được bằng chứng: ${err.message}`); });
  };

  useEffect(() => {
    if (mode !== 'legacy' || !selectedScenario) return;
    loadScenarioData(selectedScenario);
    return () => { epoch.current += 1; };
  }, [selectedScenario, mode]);

  const handleExperimental = async (query: string, preset?: ExperimentalPreset,
    selection?: { scenario_id: string; branch: ExperimentalBranch }) => {
    if (savedView) { setErrorMessage('Đang xem bản đã lưu, không gửi yêu cầu LLM.'); return; }
    if (inFlight.current || !query.trim()) return;
    inFlight.current = true;
    clearResult();
    const token = epoch.current;
    const request = { query: query.trim(), scenario_id: selection?.scenario_id || selectedScenario, branch: selection?.branch || branch };
    setIsLoading(true);
    try {
      const response = preset
        ? await experimentalApi<ExperimentalResponse>(`saved?case_id=${encodeURIComponent(preset.case_id)}&branch=${request.branch}`)
        : await runExperimental(request, liveEnabled, data => { if (token === epoch.current) setConfiguration(data); });
      assertCurrentRequest(response, request);
      if (token === epoch.current) {
        setExperimentalResponse({ ...response, display_origin: preset ? 'saved' : 'fresh' });
        setConfiguration(previous => previous ? { ...previous, ...response.configuration } : previous);
      }
    } catch (err) {
      if (token === epoch.current) setErrorMessage(String(err));
    } finally {
      inFlight.current = false;
      setIsLoading(false);
    }
  };

  const loadDemo = async (preset: ExperimentalPreset, verifiedConfig = configuration) => {
    if (!verifiedConfig || !initialOfflineDemo(verifiedConfig) || inFlight.current) return;
    setSelectedScenario(preset.scenario_id); setExperimentalQuery(preset.query); setBranch('graphrag'); setLiveEnabled(false);
    await handleExperimental(preset.query, undefined, { scenario_id: preset.scenario_id, branch: 'graphrag' });
  };

  // 3. Handle Threat Hunting query from ChatPanel
  const handleHunt = async (query: string, enforceGate: boolean, useLLM: boolean): Promise<HuntResponse | null> => {
    if (mode !== 'legacy' || inFlight.current) return null;
    inFlight.current = true;
    clearResult();
    const token = epoch.current;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          scenario_id: selectedScenario,
          enforce_gate: enforceGate,
          use_llm: useLLM,
        }),
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }

      const data: HuntResponse = await resp.json();
      if (token !== epoch.current) return null;

      if (data.status !== 'abstained' && data.subgraph && data.subgraph.elements.length > 0) {
        setGraphElements(data.subgraph.elements);
        const firstNode = data.subgraph.elements.find((el) => !el.data.source);
        if (firstNode) {
          setSelectedNode(firstNode.data);
        }
      }

      return data;
    } catch (err: any) {
      console.error('Hunt request failed:', err);
      if (token === epoch.current) setErrorMessage(`Lỗi truy vấn: ${err.message}`);
      return null;
    } finally {
      inFlight.current = false;
      setIsLoading(false);
    }
  };

  return (
    <div className="dashboard-viewport flex items-center justify-center w-full min-h-0 min-w-0 p-3 overflow-hidden select-none bg-cover bg-center">
      {/* MacOS Floating Glass Window Container */}
      <div className="flex flex-col h-full min-h-0 min-w-0 w-full max-w-[1920px] glass-panel border rounded-2xl overflow-hidden shadow-2xl relative">
        {/* Glass Header */}
        <header className="min-h-12 shrink-0 min-w-0 border-b px-4 py-2 flex flex-wrap gap-2 items-center justify-between z-10 glass-card" style={{ borderColor: 'var(--border-glass)' }}>
          {/* Left: Cyber Graph Shield Logo & Title */}
          <div className="flex items-center gap-3">
            <CyberGraphShieldIcon className="w-6 h-6" />
            <div className="flex items-center gap-2">
              <span className="font-bold text-xs tracking-wider uppercase font-mono">SOC THREAT HUNTING</span>
              <span className="text-[10px] text-soc-muted font-mono hidden md:inline">• GraphRAG & LLM Co-Pilot</span>
            </div>
            <div className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>{sourceReviewMode ? 'Demo dữ liệu thật' : mode === 'experimental' ? 'Experimental' : 'Legacy'}</span>
            </div>
          </div>

          {/* Right: Actions & Theme Toggle */}
          <div className="flex items-center gap-2.5 text-xs">
            <button type="button" onClick={resetLayout} className="glass-card border px-2 py-1.5 rounded-xl text-[11px] text-cyan-400 whitespace-nowrap"
              title="Khôi phục chiều rộng ba cột và chiều cao cấu hình chat">Khôi phục bố cục</button>
            {errorMessage ? (
              <span title={errorMessage} className="text-rose-400 text-[10px] font-mono bg-rose-950/40 px-2 py-0.5 rounded-lg border border-rose-900 max-w-[260px] truncate">
                ⚠️ {errorMessage}
              </span>
            ) : (
              <div className="hidden sm:flex items-center gap-1.5 text-[10px] font-mono text-soc-muted">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                <span>{sourceReviewMode ? 'Phân tích offline · không gọi LLM' : `Backend: ${mode === 'experimental' ? '/experimental-api' : '127.0.0.1:8000'}`}</span>
              </div>
            )}

            <button
              onClick={() => {
                const preset = sourceReviewMode ? configuration?.presets.find(p => p.scenario_id === selectedScenario) : null;
                if (preset) { void loadDemo(preset); return; }
                clearResult(); if (mode === 'legacy') loadScenarioData(selectedScenario);
              }}
              disabled={isLoading}
              className="flex items-center gap-1.5 text-soc-muted hover:text-white glass-card border px-2.5 py-1.5 rounded-xl transition text-[11px] font-mono shadow-sm"
              title={sourceReviewMode ? 'Mở lại demo của kịch bản đang chọn' : mode === 'experimental' ? 'Xóa kết quả hiện tại' : 'Tải lại toàn cảnh đồ thị'}
            >
              <RefreshIcon className="w-3 h-3 text-cyan-400" />
              <span className="hidden sm:inline">{sourceReviewMode ? 'Mở lại demo' : mode === 'experimental' ? 'Xóa kết quả' : 'Toàn cảnh'}</span>
            </button>

            {/* Theme Toggle Button (1 duy nhất) */}
            <button
              onClick={toggleTheme}
              className="p-1.5 glass-card border text-soc-muted hover:text-white rounded-xl transition shadow-sm"
              title={theme === 'dark' ? 'Chuyển sang Giao diện Sáng' : 'Chuyển sang Giao diện Tối'}
            >
              {theme === 'dark' ? <SunIcon className="w-4 h-4 text-amber-400" /> : <MoonIcon className="w-4 h-4 text-cyan-600" />}
            </button>
          </div>
        </header>

        {/* Main 3-Pane Layout: Left (Evidence) | Center (Graph) | Right (Chat) */}
        <div className="flex-1 min-h-0 min-w-0 overflow-auto">
        <main ref={splitRef} className="dashboard-splits h-full grid grid-rows-[minmax(0,1fr)] overflow-hidden"
          style={{ minWidth: MIN_LAYOUT_WIDTH, minHeight: 440, gridTemplateColumns: `${widths[0]}px ${DIVIDER_SIZE}px ${widths[1]}px ${DIVIDER_SIZE}px ${widths[2]}px` }}>
          {/* Left Column: Forensic Evidence Sidebar (3 cols) */}
          <section id="evidence-pane" className="h-full min-h-0 overflow-hidden min-w-0">
            <EvidenceSidebar
              selectedNode={selectedNode}
              evidenceItems={evidenceItems}
              theme={theme}
              experimental={mode === 'experimental' ? { response: experimentalResponse } : undefined}
            />
          </section>

          <PaneDivider orientation="vertical" label="Đổi chiều rộng bằng chứng và đồ thị" controls="evidence-pane graph-pane"
            value={widths[0]} min={COLUMN_MINIMUMS[0]} max={widths[0] + widths[1] - COLUMN_MINIMUMS[1]}
            onDelta={delta => setColumns(resizeColumns(widths, 0, delta))} onReset={resetLayout} />

          {/* Center Column: Cytoscape Knowledge Graph Canvas (5 cols) */}
          <section id="graph-pane" className="h-full min-h-0 p-2.5 overflow-hidden min-w-0 flex flex-col gap-2" data-testid="graph-pane" data-element-count={displayedGraph.length}>
            {sourceReviewMode && <div className="shrink-0 flex justify-between gap-2 px-2 py-1 text-[10px] text-soc-muted"><span>ĐỒ THỊ QUAN HỆ · {branch === 'graphrag' ? 'theo nguồn truy xuất' : 'chọn GraphRAG để khám phá'}</span><span>{displayedGraph.filter(e => !e.data.source).length} nodes</span></div>}
            <div className="flex-1 min-h-0">
            {displayedGraph.length > 0 ? (
              <CytoscapeGraph
                elements={displayedGraph}
                onSelectNode={(nodeData) => setSelectedNode(nodeData)}
                selectedNodeId={selectedNode?.id}
                theme={theme}
              />
            ) : (
              <div className="w-full h-full flex flex-col items-center justify-center text-soc-muted border rounded-2xl glass-card">
                {isLoading && <div className="animate-spin text-cyan-400 mb-2">⏳</div>}
                <p className="text-xs font-mono text-center px-5" data-testid="graph-empty">{mode === 'legacy' ? 'Đang nạp đồ thị tri thức...' :
                  isLoading ? 'Đang xử lý câu hỏi mới; graph cũ đã được xóa.' :
                  experimentalResponse?.outcome === 'abstain' ? 'Chọn một kịch bản demo hoặc đặt câu hỏi có tên tiến trình để xem đồ thị.' :
                  branch === 'rag' ? 'RAG chỉ dùng retrieval evidence; không có graph.' :
                  'Đang chuẩn bị đồ thị. Chọn một kịch bản để bắt đầu trình diễn.'}</p>
              </div>
            )}
            </div>
          </section>

          <PaneDivider orientation="vertical" label="Đổi chiều rộng đồ thị và chat" controls="graph-pane chat-pane"
            value={widths[1]} min={COLUMN_MINIMUMS[1]} max={widths[1] + widths[2] - COLUMN_MINIMUMS[2]}
            onDelta={delta => setColumns(resizeColumns(widths, 1, delta))} onReset={resetLayout} />

          {/* Right Column: Threat Hunting Chat Panel (4 cols) */}
          <section id="chat-pane" className="h-full min-h-0 overflow-hidden min-w-0">
            <ChatPanel
              key={mode === 'legacy' ? selectedScenario : 'experimental'}
              scenarios={scenarios}
              selectedScenario={selectedScenario}
              onSelectScenario={selectScenario}
              onHunt={handleHunt}
              isLoading={isLoading}
              theme={theme}
              settingsRatio={settingsRatio}
              onSettingsRatioChange={setSettingsRatio}
              mode={mode}
              onModeChange={selectMode}
              experimental={mode === 'experimental' ? {
                configuration, response: experimentalResponse, branch, query: experimentalQuery, liveEnabled,
                savedView, onSavedView: () => showSavedResult(),
                error: errorMessage,
                onBranchChange: value => {
                  setBranch(value);
                  if (sourceReviewMode && experimentalQuery.trim()) { void handleExperimental(experimentalQuery, undefined, { scenario_id: selectedScenario, branch: value }); }
                  else clearResult();
                },
                onQueryChange: value => { if (!sourceReviewMode) clearResult(); setExperimentalQuery(value); },
                onDemo: preset => loadDemo(preset),
                onPreset: preset => { clearResult(); setSelectedScenario(preset.scenario_id); setExperimentalQuery(preset.query); },
                onProfileChange: async profile => {
                  if (inFlight.current) return;
                  clearResult(); setLiveEnabled(false); setConfiguration(null); selectArtifactProfile(profile);
                  const token = epoch.current;
                  inFlight.current = true; setIsLoading(true);
                  try {
                    const data = await experimentalApi<ExperimentalConfiguration>('config');
                    if (token === epoch.current) setConfiguration(data);
                  } catch (err) { if (token === epoch.current) setErrorMessage(String(err)); }
                  finally { inFlight.current = false; setIsLoading(false); }
                },
                onLiveChange: value => { clearResult(); setLiveEnabled(value); },
                onHunt: query => handleExperimental(query),
                onReplay: preset => handleExperimental(preset.query, preset),
              } : undefined}
            />
          </section>
        </main>
        </div>

        {/* MacOS Style Footer Shortcut Hints Bar (như mẫu RLESS) */}
        <footer className="h-7 shrink-0 min-w-0 border-t px-4 flex items-center justify-between text-[10px] font-mono text-soc-muted glass-card select-none" style={{ borderColor: 'var(--border-glass)' }}>
          {sourceReviewMode ? <div>Chọn kịch bản · khám phá quan hệ · đối chiếu bằng chứng nguồn</div> : <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>Tab</kbd>
              <span>Đổi kịch bản</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>D</kbd>
              <span>Sáng / Tối</span>
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <kbd className="px-1 py-0.2 rounded bg-black/40 border text-gray-300 font-bold" style={{ borderColor: 'var(--border-glass)' }}>G</kbd>
              <span>Toàn cảnh đồ thị</span>
            </span>
          </div>}

          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-emerald-400 font-semibold uppercase">Học viện Kỹ thuật Mật mã — 2026</span>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default App;
