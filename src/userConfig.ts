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
  /** 그래프 DB(graph-db.json)가 저장되는 폴더 절대 경로. null이면 기본값 사용 */
  dbDir: string | null;
}

const DEFAULT_CONFIG: UserConfig = { lastProjectPath: null, updatedAt: null, dbDir: null };

/** 그래프 DB 기본 폴더 (<home>/.sentinelnode) */
export function defaultDbDir(): string {
  return path.join(os.homedir(), '.sentinelnode');
}

/** 그래프 DB 기본 파일 경로 */
export function defaultDbFilePath(): string {
  return path.join(defaultDbDir(), 'graph-db.json');
}

/** 설정에 저장된 DB 폴더 (없거나 유효하지 않으면 기본값) */
export function resolveDbDir(config?: UserConfig): string {
  const dir = config?.dbDir;
  if (typeof dir === 'string' && dir.length > 0) return dir;
  return defaultDbDir();
}

/** DB 파일 경로 (폴더 + graph-db.json) */
export function resolveDbFilePath(config?: UserConfig): string {
  return path.join(resolveDbDir(config), 'graph-db.json');
}

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

function isValidDbDir(p: unknown): p is string {
  if (typeof p !== 'string' || p.length === 0) return false;
  try {
    // 존재하지 않는 경로는 생성 가능하면 유효 (부모 존재 여부로 판단)
    if (fs.existsSync(p)) return fs.statSync(p).isDirectory();
    const parent = path.dirname(p);
    return fs.existsSync(parent) && fs.statSync(parent).isDirectory();
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
    const dbDir =
      typeof parsed.dbDir === 'string' && isValidDbDir(parsed.dbDir) ? parsed.dbDir : null;
    return { lastProjectPath, updatedAt: parsed.updatedAt ?? null, dbDir };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/** 마지막 검색 폴더 저장 (기존 DB 폴더 설정 유지) */
export function saveLastProjectPath(dirPath: string, file = configPath()): UserConfig {
  const prev = loadUserConfig(file);
  const config: UserConfig = {
    lastProjectPath: dirPath,
    updatedAt: new Date().toISOString(),
    dbDir: prev.dbDir,
  };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(config, null, 2), 'utf-8');
  return config;
}

/** 그래프 DB 폴더 저장 (없으면 생성, 유효성 검사 후 보관) */
export function saveDbDir(dirPath: string, file = configPath()): UserConfig {
  if (!isValidDbDir(dirPath)) {
    throw new Error('DB 폴더 경로가 유효하지 않습니다.');
  }
  fs.mkdirSync(dirPath, { recursive: true });
  if (!fs.statSync(dirPath).isDirectory()) {
    throw new Error('DB 폴더가 디렉토리가 아닙니다.');
  }
  const prev = loadUserConfig(file);
  const config: UserConfig = {
    lastProjectPath: prev.lastProjectPath,
    updatedAt: new Date().toISOString(),
    dbDir: path.resolve(dirPath),
  };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(config, null, 2), 'utf-8');
  return config;
}

/** 그래프 DB 폴더를 기본값으로 초기화 */
export function resetDbDir(file = configPath()): UserConfig {
  const prev = loadUserConfig(file);
  const config: UserConfig = {
    lastProjectPath: prev.lastProjectPath,
    updatedAt: new Date().toISOString(),
    dbDir: null,
  };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(config, null, 2), 'utf-8');
  return config;
}
