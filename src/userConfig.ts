/**
 * 사용자 정의 파일 — 마지막 검색 프로젝트 폴더 등 사용자 설정을
 * 그래프 DB 옆 config.json에 보관한다.
 *
 * 경로: <os.homedir()>/.sentinelnode/config.json
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface UserConfig {
  /** 마지막으로 검색(스캔)한 프로젝트 폴더 절대 경로 */
  lastProjectPath: string | null;
  updatedAt: string | null;
}

const DEFAULT_CONFIG: UserConfig = { lastProjectPath: null, updatedAt: null };

export function configPath(): string {
  return path.join(os.homedir(), '.sentinelnode', 'config.json');
}

function isValidProjectPath(p: unknown): p is string {
  if (typeof p !== 'string' || p.length === 0) return false;
  try {
    return fs.existsSync(p) && fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** 저장된 설정 읽기 (파일 없음·손상·경로 소멸 시 기본값) */
export function loadUserConfig(file = configPath()): UserConfig {
  try {
    if (!fs.existsSync(file)) return { ...DEFAULT_CONFIG };
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as Partial<UserConfig>;
    const lastProjectPath = isValidProjectPath(parsed.lastProjectPath)
      ? (parsed.lastProjectPath as string)
      : null;
    return { lastProjectPath, updatedAt: parsed.updatedAt ?? null };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/** 마지막 검색 폴더 저장 */
export function saveLastProjectPath(dirPath: string, file = configPath()): UserConfig {
  const config: UserConfig = {
    lastProjectPath: dirPath,
    updatedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(config, null, 2), 'utf-8');
  return config;
}
