import React, { useState } from 'react';

// Preload를 통해 노출된 API 타입 선언
declare global {
  interface Window {
    sentinelAPI: {
      selectDirectory: () => Promise<string | null>;
      runAstScan: (dirPath: string) => Promise<{ success: boolean; reports?: any[]; error?: string }>;
    };
  }
}

interface VulnerabilityReport {
  file: string;
  line: number;
  type: string;
  message: string;
}

export default function App() {
  const [targetPath, setTargetPath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [reports, setReports] = useState<VulnerabilityReport[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // 1. 폴더 선택 다이얼로그 호출
  const handleSelectFolder = async () => {
    const path = await window.sentinelAPI.selectDirectory();
    if (path) {
      setTargetPath(path);
      setReports([]);
      setErrorMsg(null);
    }
  };

  // 2. AST 스캔 실행
  const handleRunScan = async () => {
    if (!targetPath) return;

    setLoading(true);
    setErrorMsg(null);

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
          <h1 className="text-xl font-bold tracking-wider text-indigo-600">SentinelNode</h1>
          <p className="text-xs text-slate-500">AST 기반 로컬 소스 코드 취약점 및 코딩 실수 진단 엔진</p>
        </div>
        <div className="text-xs text-slate-500 font-mono">Engine: Babel AST Parser</div>
      </header>

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
        </div>

        {errorMsg && (
          <div className="text-xs text-rose-600 bg-rose-50 border border-rose-200 px-3 py-2 rounded">
            {errorMsg}
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
            {reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400 text-sm gap-1">
                <p>탐지된 코딩 실수가 없습니다.</p>
                <span className="text-xs text-slate-400">프로젝트를 선택하고 검사를 시작하세요.</span>
              </div>
            ) : (
              reports.map((report, idx) => (
                <div key={idx} className="px-6 py-3.5 grid grid-cols-12 gap-4 items-center text-sm hover:bg-slate-50 transition">
                  {/* 유형 뱃지 */}
                  <div className="col-span-2">
                    <span className="px-2.5 py-1 rounded-md text-xs font-bold font-mono bg-rose-50 text-rose-600 border border-rose-200">
                      {report.type}
                    </span>
                  </div>
                  {/* 파일 경로 (길면 말줄임) */}
                  <div className="col-span-5 font-mono text-xs text-slate-700 truncate" title={report.file}>
                    {report.file}
                  </div>
                  {/* 라인 번호 */}
                  <div className="col-span-1 text-center font-mono text-xs text-slate-500">
                    :{report.line}
                  </div>
                  {/* 설명 */}
                  <div className="col-span-4 text-xs text-slate-600 truncate" title={report.message}>
                    {report.message}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}