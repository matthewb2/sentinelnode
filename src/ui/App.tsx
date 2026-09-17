import React, { useEffect, useState } from 'react';

// Preload를 통해 노출된 API 타입 선언
declare global {
  interface Window {
    sentinelAPI: {
      selectDirectory: () => Promise<string | null>;
      runAstScan: (dirPath: string) => Promise<{ success: boolean; reports?: any[]; error?: string }>;
      getDbStats: () => Promise<
        | { success: true; stats: { vulnerabilities: number; relations: number }; storagePath: string }
        | { success: false; error: string }
      >;
      getSyncStatus: () => Promise<
        | { success: true; status: SyncStatusState }
        | { success: false; error: string }
      >;
      checkCveUpdates: () => Promise<
        | { success: true; updateAvailable: boolean; latestTag: string | null }
        | { success: false; error: string }
      >;
      syncCveNow: (opts?: object) => Promise<{ success: boolean; ingested?: number; scanned?: number; error?: string }>;
      importCveDir: (payload?: object) => Promise<{ success: boolean; ingested?: number; scanned?: number; error?: string }>;
      fetchCve: (cveId: string) => Promise<{ success: boolean; ingested?: number; error?: string }>;
      setAutoSync: (enabled: boolean) => Promise<{ success: boolean; autoSync?: boolean }>;
      getAiFix: (payload: {
        file: string;
        line: number;
        type: string;
        message: string;
        cveId?: string;
        severity?: string;
        package?: string;
      }) => Promise<
        | { success: true; fixedCode: string; explanation: string; snippetStartLine: number; cached: boolean }
        | { success: false; error: string }
      >;
      openInVscode: (payload: { file?: string; line?: number }) => Promise<
        { success: true } | { success: false; error: string }
      >;
      getUserConfig: () => Promise<
        | { success: true; config: { lastProjectPath: string | null; updatedAt: string | null } }
        | { success: false; error: string }
      >;
      onCveSyncDone?: (cb: (info: { updated: boolean; ingested: number; tag: string | null }) => void) => () => void;
    };
  }
}

interface SyncStatusState {
  lastCheckAt: string | null;
  lastSyncAt: string | null;
  lastReleaseTag: string | null;
  updateAvailable: boolean;
  latestTag: string | null;
  autoSync: boolean;
  ingestedTotal: number;
  lastSource: string | null;
  watchlistSize: number;
}

interface VulnerabilityReport {
  file: string;
  line: number;
  type: string;
  message: string;
  cveId?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  package?: string;
}

interface AiPanelState {
  status: 'loading' | 'done' | 'error';
  fixedCode?: string;
  explanation?: string;
  error?: string;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-300',
  high: 'bg-rose-50 text-rose-600 border-rose-200',
  medium: 'bg-amber-50 text-amber-700 border-amber-200',
  low: 'bg-sky-50 text-sky-700 border-sky-200',
  info: 'bg-slate-100 text-slate-600 border-slate-200',
};

export default function App() {
  const [targetPath, setTargetPath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [reports, setReports] = useState<VulnerabilityReport[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [dbInfo, setDbInfo] = useState<string | null>(null);
  const [syncStatus, setSyncStatus] = useState<SyncStatusState | null>(null);
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [cveIdInput, setCveIdInput] = useState('');
  const [aiPanels, setAiPanels] = useState<Record<number, AiPanelState>>({});
  const [vscodeMsg, setVscodeMsg] = useState<string | null>(null);

  const refreshDbInfo = async () => {
    try {
      const res = await window.sentinelAPI?.getDbStats?.();
      if (res && res.success) {
        setDbInfo(`GraphDB · 패턴 ${res.stats.vulnerabilities}개 · 릴레이션 ${res.stats.relations}개`);
      }
    } catch {
      // 브라우저 미리보기 등 비-Electron 환경 무시
    }
    try {
      const res = await window.sentinelAPI?.getSyncStatus?.();
      if (res && res.success) setSyncStatus(res.status);
    } catch {
      // 비-Electron 환경 무시
    }
  };

  // 그래프 DB 상태 + CVE 동기화 상태 + 저장된 폴더 조회 (Electron 환경에서만 동작)
  useEffect(() => {
    void refreshDbInfo();
    // 마지막 검색 폴더를 기본값으로 복원
    window.sentinelAPI
      ?.getUserConfig?.()
      .then((res) => {
        if (res.success && res.config.lastProjectPath) {
          setTargetPath(res.config.lastProjectPath);
        }
      })
      .catch(() => undefined);
    const off = window.sentinelAPI?.onCveSyncDone?.((info) => {
      if (info.updated) {
        setSyncMsg(`시작 시 자동 반영됨: ${info.ingested}건 (${info.tag ?? 'delta'})`);
        void refreshDbInfo();
      }
    });
    return () => {
      off?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCheckUpdates = async () => {
    setSyncBusy(true);
    setSyncMsg(null);
    try {
      const res = await window.sentinelAPI.checkCveUpdates();
      if (res.success) {
        setSyncMsg(
          res.updateAvailable
            ? `새 CVE 릴리스 있음 (${res.latestTag ?? 'unknown'}) — [지금 업데이트]를 눌러 반영하세요.`
            : '최신 상태입니다.',
        );
        await refreshDbInfo();
      } else {
        setSyncMsg(res.error || '업데이트 확인 실패 (오프라인 가능)');
      }
    } catch (err: any) {
      setSyncMsg(err.message || '업데이트 확인 실패');
    } finally {
      setSyncBusy(false);
    }
  };

  const handleSyncNow = async () => {
    setSyncBusy(true);
    setSyncMsg(null);
    try {
      const res = await window.sentinelAPI.syncCveNow();
      if (res.success) {
        setSyncMsg(`반영 완료: 스캔 ${res.scanned ?? 0}건 중 ${res.ingested ?? 0}건 적재`);
        await refreshDbInfo();
      } else {
        setSyncMsg(res.error || '업데이트 실패');
      }
    } catch (err: any) {
      setSyncMsg(err.message || '업데이트 실패');
    } finally {
      setSyncBusy(false);
    }
  };

  const handleImportDir = async () => {
    setSyncBusy(true);
    setSyncMsg(null);
    try {
      const res = await window.sentinelAPI.importCveDir();
      if (res.success) {
        setSyncMsg(`로컬 클론 반영 완료: 스캔 ${res.scanned ?? 0}건 중 ${res.ingested ?? 0}건 적재`);
        await refreshDbInfo();
      } else {
        setSyncMsg(res.error || '가져오기 실패');
      }
    } catch (err: any) {
      setSyncMsg(err.message || '가져오기 실패');
    } finally {
      setSyncBusy(false);
    }
  };

  const handleFetchCve = async () => {
    const id = cveIdInput.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(id)) {
      setSyncMsg('CVE ID 형식이 아닙니다. 예: CVE-2020-28500');
      return;
    }
    setSyncBusy(true);
    setSyncMsg(null);
    try {
      const res = await window.sentinelAPI.fetchCve(id);
      if (res.success) {
        setSyncMsg(`${id} 반영 완료 (${res.ingested ?? 0}건)`);
        setCveIdInput('');
        await refreshDbInfo();
      } else {
        setSyncMsg(res.error || '가져오기 실패');
      }
    } catch (err: any) {
      setSyncMsg(err.message || '가져오기 실패');
    } finally {
      setSyncBusy(false);
    }
  };

  const handleToggleAutoSync = async () => {
    const next = !(syncStatus?.autoSync ?? true);
    try {
      const res = await window.sentinelAPI.setAutoSync(next);
      if (res.success) await refreshDbInfo();
    } catch {
      // 무시
    }
  };

  // 1. 폴더 선택 다이얼로그 호출
  const handleSelectFolder = async () => {
    const path = await window.sentinelAPI.selectDirectory();
    if (path) {
      setTargetPath(path);
      setReports([]);
      setAiPanels({});
      setErrorMsg(null);
    }
  };

  // 3. AI 수정 제안 (Groq 질의)
  const handleAiFix = async (idx: number, report: VulnerabilityReport) => {
    setAiPanels((prev) => ({ ...prev, [idx]: { status: 'loading' } }));
    try {
      const res = await window.sentinelAPI.getAiFix({
        file: report.file,
        line: report.line,
        type: report.type,
        message: report.message,
        cveId: report.cveId,
        severity: report.severity,
        package: report.package,
      });
      if (res.success) {
        setAiPanels((prev) => ({
          ...prev,
          [idx]: { status: 'done', fixedCode: res.fixedCode, explanation: res.explanation },
        }));
      } else {
        setAiPanels((prev) => ({ ...prev, [idx]: { status: 'error', error: res.error } }));
      }
    } catch (err: any) {
      setAiPanels((prev) => ({ ...prev, [idx]: { status: 'error', error: err.message || 'AI 질의 실패' } }));
    }
  };

  const toggleAiPanel = (idx: number) => {
    setAiPanels((prev) => {
      if (prev[idx]) {
        const next = { ...prev };
        delete next[idx];
        return next;
      }
      return prev;
    });
  };

  // 4. VS Code로 열기 (해당 파일·라인 또는 프로젝트 폴더)
  const handleOpenVscode = async (file?: string, line?: number) => {
    setVscodeMsg(null);
    try {
      const res = await window.sentinelAPI.openInVscode({ file, line });
      if (!res.success) setVscodeMsg(res.error);
    } catch (err: any) {
      setVscodeMsg(err.message || 'VS Code 실행 실패');
    }
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setVscodeMsg('추천 코드를 클립보드에 복사했습니다.');
    } catch {
      setVscodeMsg('클립보드 복사에 실패했습니다.');
    }
  };

  // 2. AST 스캔 실행
  const handleRunScan = async () => {
    if (!targetPath) return;

    setLoading(true);
    setErrorMsg(null);
    setAiPanels({});
    setVscodeMsg(null);

    try {
      const result = await window.sentinelAPI.runAstScan(targetPath);
      if (result.success && result.reports) {
        setReports(result.reports);
      } else {
        setErrorMsg(result.error || '스캔 중 오류가 발생했습니다.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || '알 수 없는 오류 발생');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-white text-slate-900 font-sans select-none">
      {/* 상단 헤더 영역 */}
      <header className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-white/90 backdrop-blur">
        <div>          
          <p className="text-xs text-slate-500">AST 기반 로컬 소스 코드 취약점 및 코딩 실수 진단 엔진</p>
        </div>
        <div className="text-xs text-slate-500 font-mono">Engine: Babel AST Parser</div>
      </header>
      {dbInfo && (
        <div className="px-6 py-1.5 text-[11px] font-mono text-slate-500 bg-slate-50 border-b border-slate-200">
          {dbInfo}
        </div>
      )}

      {/* 컨트롤 패널 영역 */}
      <div className="p-6 pb-4 flex flex-col gap-3 border-b border-slate-200 bg-slate-50">
        <div className="flex gap-3 items-center">
          <button
            onClick={handleSelectFolder}
            className="bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 px-4 py-2 rounded-lg text-sm font-medium transition shadow-sm"
          >
            프로젝트 폴더 선택
          </button>
          
          <div className="flex-1 bg-white border border-slate-200 rounded-lg px-4 py-2 text-sm text-slate-600 font-mono truncate">
            {targetPath ? targetPath : '선택된 폴더가 없습니다.'}
          </div>

          <button
            onClick={handleRunScan}
            disabled={!targetPath || loading}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-6 py-2 rounded-lg text-sm font-semibold transition shadow-md shadow-indigo-600/20"
          >
            {loading ? 'AST 분석 중...' : '취약점 검사 시작'}
          </button>

          <button
            onClick={() => void handleOpenVscode()}
            disabled={!targetPath}
            title="프로젝트 폴더를 VS Code로 열기"
            className="bg-white hover:bg-slate-100 disabled:opacity-40 border border-slate-300 text-slate-700 px-4 py-2 rounded-lg text-sm font-medium transition shadow-sm"
          >
            VS Code로 열기
          </button>
        </div>

        {vscodeMsg && (
          <div className="text-xs text-slate-600 bg-white border border-slate-200 px-3 py-2 rounded">
            {vscodeMsg}
          </div>
        )}

        {errorMsg && (
          <div className="text-xs text-rose-600 bg-rose-50 border border-rose-200 px-3 py-2 rounded">
            {errorMsg}
          </div>
        )}
      </div>

      {/* CVE 데이터베이스 패널 (수동 업데이트) */}
      <div className="px-6 py-3 flex flex-col gap-2 border-b border-slate-200 bg-white">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider mr-2">
            CVE 데이터베이스
          </h2>
          {syncStatus && (
            <span
              className={`px-2 py-0.5 rounded-md text-[11px] font-bold border ${
                syncStatus.updateAvailable
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}
            >
              {syncStatus.updateAvailable ? '업데이트 있음' : '최신'}
            </span>
          )}
          <span className="text-[11px] font-mono text-slate-500">
            {syncStatus
              ? `릴리스 ${syncStatus.lastReleaseTag ?? '-'} → ${syncStatus.latestTag ?? '-'} · 관심 패키지 ${syncStatus.watchlistSize}개 · 누적 ${syncStatus.ingestedTotal}건`
              : '동기화 상태 조회 중…'}
          </span>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer">
            <input
              type="checkbox"
              checked={syncStatus?.autoSync ?? true}
              onChange={handleToggleAutoSync}
              className="accent-indigo-600"
            />
            시작 시 자동 업데이트
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleCheckUpdates}
            disabled={syncBusy}
            className="bg-white hover:bg-slate-100 disabled:opacity-40 border border-slate-300 text-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition shadow-sm"
          >
            {syncBusy ? '확인 중…' : '업데이트 확인'}
          </button>
          <button
            onClick={handleSyncNow}
            disabled={syncBusy}
            className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition shadow-sm"
          >
            지금 업데이트
          </button>
          <button
            onClick={handleImportDir}
            disabled={syncBusy}
            className="bg-white hover:bg-slate-100 disabled:opacity-40 border border-slate-300 text-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition shadow-sm"
          >
            클론 폴더 가져오기
          </button>
          <input
            value={cveIdInput}
            onChange={(e) => setCveIdInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void handleFetchCve();
            }}
            placeholder="CVE-2020-28500"
            spellCheck={false}
            className="bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-700 w-44 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button
            onClick={handleFetchCve}
            disabled={syncBusy || !cveIdInput.trim()}
            className="bg-white hover:bg-slate-100 disabled:opacity-40 border border-slate-300 text-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition shadow-sm"
          >
            CVE 가져오기
          </button>
        </div>
        {syncMsg && (
          <div className="text-xs text-slate-600 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded">
            {syncMsg}
          </div>
        )}
      </div>

      {/* 결과 대시보드 그리드 영역 */}
      <div className="flex-1 p-6 overflow-hidden flex flex-col bg-white">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider">
            진단 리포트 <span className="text-indigo-600 font-mono ml-1">({reports.length} 건 탐지됨)</span>
          </h2>
        </div>

        <div className="flex-1 bg-white border border-slate-200 rounded-xl overflow-hidden flex flex-col shadow-sm">
          {/* 테이블 헤더 */}
          <div className="bg-slate-50 border-b border-slate-200 px-6 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider grid grid-cols-12 gap-4">
            <div className="col-span-2">취약점 유형</div>
            <div className="col-span-5">파일 경로</div>
            <div className="col-span-1 text-center">라인</div>
            <div className="col-span-4">상세 설명 / 실수 내용</div>
          </div>

          {/* 테이블 바디 (스크롤 영역) */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
            {loading ? (
              <div
                role="status"
                aria-label="AST 분석 중"
                className="flex flex-col items-center justify-center h-full gap-3 text-sm text-slate-500"
              >
                <span className="h-8 w-8 rounded-full border-2 border-slate-200 border-t-indigo-600 animate-spin" />
                <p className="font-medium">AST 분석 중…</p>
                <span className="text-xs text-slate-400">소스코드 파싱 및 취약점 패턴 대조 중입니다.</span>
              </div>
            ) : reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400 text-sm gap-1">
                <p>탐지된 코딩 실수가 없습니다.</p>
                <span className="text-xs text-slate-400">프로젝트를 선택하고 검사를 시작하세요.</span>
              </div>
            ) : (
              reports.map((report, idx) => {
                const panel = aiPanels[idx];
                return (
                <React.Fragment key={idx}>
                <div className="px-6 py-3.5 grid grid-cols-12 gap-4 items-center text-sm hover:bg-slate-50 transition">
                  {/* 유형 뱃지 */}
                  <div className="col-span-2 flex flex-wrap gap-1">
                    <span className="px-2.5 py-1 rounded-md text-xs font-bold font-mono bg-rose-50 text-rose-600 border border-rose-200">
                      {report.type}
                    </span>
                    {report.cveId && (
                      <span className="px-2 py-1 rounded-md text-[11px] font-mono bg-slate-100 text-slate-600 border border-slate-200">
                        {report.cveId}
                      </span>
                    )}
                    {report.severity && (
                      <span
                        className={`px-2 py-1 rounded-md text-[11px] font-bold uppercase border ${SEVERITY_STYLE[report.severity] ?? SEVERITY_STYLE.info}`}
                      >
                        {report.severity}
                      </span>
                    )}
                  </div>
                  {/* 파일 경로 (길면 말줄임) */}
                  <div className="col-span-5 font-mono text-xs text-slate-700 truncate" title={report.file}>
                    {report.file}
                  </div>
                  {/* 라인 번호 */}
                  <div className="col-span-1 text-center font-mono text-xs text-slate-500">
                    :{report.line}
                  </div>
                  {/* 설명 + 액션 */}
                  <div className="col-span-4 text-xs text-slate-600 truncate" title={report.message}>
                    {report.message}
                  </div>
                  <div className="col-span-12 flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => (panel ? toggleAiPanel(idx) : void handleAiFix(idx, report))}
                      className="bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 px-3 py-1 rounded-md text-xs font-semibold transition"
                    >
                      {panel ? 'AI 제안 닫기' : 'AI 수정 제안'}
                    </button>
                    <button
                      onClick={() => void handleOpenVscode(report.file, report.line)}
                      title={`${report.file}${report.line > 0 ? `:${report.line}` : ''} 위치로 VS Code 열기`}
                      className="bg-white hover:bg-slate-100 border border-slate-300 text-slate-600 px-3 py-1 rounded-md text-xs font-medium transition"
                    >
                      VS Code로 열기
                    </button>
                  </div>
                </div>
                {panel && (
                  <div className="px-6 py-4 bg-slate-50 border-t border-slate-100">
                    {panel.status === 'loading' ? (
                      <div role="status" aria-label="AI 추천 생성 중" className="flex items-center gap-3 text-sm text-slate-500">
                        <span className="h-5 w-5 rounded-full border-2 border-slate-200 border-t-indigo-600 animate-spin" />
                        <span>Groq AI가 수정 코드를 생성 중입니다…</span>
                      </div>
                    ) : panel.status === 'error' ? (
                      <div className="text-xs text-rose-600 bg-rose-50 border border-rose-200 px-3 py-2 rounded">
                        {panel.error}
                        <button
                          onClick={() => void handleAiFix(idx, report)}
                          className="ml-3 underline font-semibold"
                        >
                          다시 시도
                        </button>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <p className="text-xs text-slate-600 leading-relaxed">{panel.explanation}</p>
                        <pre className="text-xs font-mono text-slate-800 bg-white border border-slate-200 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap select-text">
                          {panel.fixedCode}
                        </pre>
                        <div className="flex flex-wrap gap-2">
                          <button
                            onClick={() => void handleCopy(panel.fixedCode ?? '')}
                            className="bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 px-3 py-1 rounded-md text-xs font-medium transition"
                          >
                            코드 복사
                          </button>
                          <button
                            onClick={() => void handleOpenVscode(report.file, report.line)}
                            className="bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded-md text-xs font-semibold transition"
                          >
                            VS Code에서 수정하기
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
                </React.Fragment>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}