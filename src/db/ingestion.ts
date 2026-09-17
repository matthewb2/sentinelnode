/**
 * Data Ingestion Worker — 외부 CVE 피드 → 노드 스키마 정규화 → 그래프 적재.
 *
 * 워크플로우(Gemini 설계 ①→②):
 *   [CVE Feed JSON] → normalize → upsert Vulnerability Node
 *                     → ensure Package Node → link AFFECTS
 */
import axios from 'axios';
import type { GraphStore } from './graphStore';
import { SEED_VULNERABILITIES } from './seed';
import type { FeedVulnerabilityItem, VulnerabilityNode } from './types';

function slugId(title: string, index: number): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `FEED-${index}-${slug || 'vuln'}`;
}

export function normalizeFeedItem(item: FeedVulnerabilityItem, index: number): VulnerabilityNode {
  return {
    kind: 'vulnerability',
    id: item.cveId ?? slugId(item.title, index),
    cveId: item.cveId,
    title: item.title,
    description: item.description ?? item.title,
    severity: item.severity ?? 'medium',
    affectedPackage: item.affectedPackage,
    versionRange: item.versionRange,
    astSignature: item.astSignature,
    references: item.references ?? [],
    updatedAt: new Date().toISOString(),
  };
}

/** 피드 아이템 배열을 그래프 DB에 적재하고 적재된 노드 수를 반환 */
export function ingestFeed(store: GraphStore, items: FeedVulnerabilityItem[]): number {
  // 동일 CVE ID 중복 노드 방지: 기존 cveId → 노드 ID 매핑
  const cveIdToId = new Map<string, string>();
  for (const v of store.allVulnerabilities()) {
    if (v.cveId) cveIdToId.set(v.cveId, v.id);
  }
  let count = 0;
  items.forEach((item, i) => {
    if (!item.title) return;
    const node = normalizeFeedItem(item, i);
    // 이미 같은 CVE가 있으면 기존 ID에 덮어써 노드 중복 방지
    if (node.cveId && cveIdToId.has(node.cveId)) {
      node.id = cveIdToId.get(node.cveId) as string;
    } else if (node.cveId) {
      cveIdToId.set(node.cveId, node.id);
    }
    store.upsert(node);
    if (node.affectedPackage) {
      const pkg = store.ensurePackage(node.affectedPackage);
      store.link('AFFECTS', node.id, pkg.id);
    }
    count += 1;
  });
  store.save();
  return count;
}

/** 기본 시드가 비어 있을 때 1회 적재 (멱등: 고정 ID 기준 upsert) */
export function ensureSeedLoaded(store: GraphStore): number {
  const existing = new Set(store.allVulnerabilities().map((v) => v.id));
  let added = 0;
  for (const seed of SEED_VULNERABILITIES) {
    if (existing.has(seed.id)) continue;
    store.upsert({ ...seed, updatedAt: new Date().toISOString() });
    if (seed.affectedPackage) {
      const pkg = store.ensurePackage(seed.affectedPackage);
      store.link('AFFECTS', seed.id, pkg.id);
    }
    added += 1;
  }
  if (added > 0) store.save();
  return added;
}

/** 원격 피드 URL에서 JSON 배열을 내려받아 적재 (정기 동기화용) */
export async function syncFromUrl(store: GraphStore, url: string): Promise<number> {
  const res = await axios.get<FeedVulnerabilityItem[]>(url, { timeout: 15000 });
  const items = Array.isArray(res.data) ? res.data : [];
  return ingestFeed(store, items);
}
