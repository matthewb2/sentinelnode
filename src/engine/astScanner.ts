import * as fs from 'fs';
import * as path from 'path';
import * as parser from '@babel/parser';
import traverse from '@babel/traverse';

interface AstVulnerabilityReport {
  file: string;
  line: number;
  type: string;
  message: string;
}

export function runAstScan(dirPath: string): AstVulnerabilityReport[] {
  let reports: AstVulnerabilityReport[] = [];

  function walk(currentPath: string) {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build'].includes(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        // JS / TS 파일 대상
        if (/\.(ts|tsx|js|jsx)$/.test(entry.name)) {
          const code = fs.readFileSync(fullPath, 'utf-8');

          try {
            // 1. 소스 코드를 AST(추상 구문 트리)로 파싱
            const ast = parser.parse(code, {
              sourceType: 'module',
              plugins: ['typescript', 'jsx'],
            });

// 2. AST 트리 순회 (Visitor 패턴)
traverse(ast, {
  // [실수 1] eval() 함수 사용 탐지
  CallExpression(pathNode: any) {
    const callee = pathNode.node.callee;
    if (callee.type === 'Identifier' && callee.name === 'eval') {
      reports.push({
        file: fullPath,
        line: pathNode.node.loc?.start.line || 0,
        type: 'Dangerous Eval',
        message: '임의의 코드를 실행하는 eval() 함수가 사용되었습니다. 보안상 매우 위험합니다.',
      });
    }
  },

  // [실수 2] 하드코딩된 비밀번호 / 시크릿 키 탐지
  VariableDeclarator(pathNode: any) {
    if (
      pathNode.node.id.type === 'Identifier' &&
      ['password', 'secret', 'privateKey', 'api_key'].includes(pathNode.node.id.name.toLowerCase()) &&
      pathNode.node.init?.type === 'StringLiteral'
    ) {
      reports.push({
        file: fullPath,
        line: pathNode.node.loc?.start.line || 0,
        type: 'Hardcoded Secret',
        message: `변수 '${pathNode.node.id.name}'에 민감한 값이 하드코딩되어 있습니다.`,
      });
    }
  },
});
          } catch (parseError) {
            // 문법 오류가 있는 파일은 파싱 에러 스킵
            console.error(`Parse error in ${fullPath}:`, parseError);
          }
        }
      }
    }
  }

  walk(dirPath);
  return reports;
}