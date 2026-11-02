// Loads the canonical OpenAPI file (never copied) and compiles validators from it with ajv.
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { parse } from 'yaml';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';

export const SPEC_PATH = resolve(__dirname, '../../../docs/features/biometric-pin-login/openapi.yaml');

type Json = any;
export const spec: Json = parse(readFileSync(SPEC_PATH, 'utf8'));

const ajv = new Ajv2020({ strict: false, allErrors: false });
addFormats(ajv);
ajv.addFormat('int64', true);
ajv.addSchema(spec, 'spec');

export function deref(node: Json): Json {
  let n = node;
  let guard = 0;
  while (n && typeof n === 'object' && typeof n.$ref === 'string' && guard++ < 10) {
    const ptr = n.$ref as string;
    if (!ptr.startsWith('#/')) throw new Error(`unsupported ref ${ptr}`);
    n = ptr
      .slice(2)
      .split('/')
      .reduce((acc: Json, k) => acc[k.replace(/~1/g, '/').replace(/~0/g, '~')], spec);
  }
  return n;
}

export type Validator = (data: unknown) => boolean;
const cache = new Map<string, Validator>();

/** Validator for a schema node that is `{ $ref: '#/components/schemas/X' }` (all schemas in this contract are refs). */
export function validatorFor(schemaNode: Json): Validator {
  const ref: string | undefined = schemaNode?.$ref;
  if (!ref) throw new Error('inline schemas are not used in this contract');
  let v = cache.get(ref);
  if (!v) {
    const fn = ajv.getSchema(`spec${ref}`);
    if (!fn) throw new Error(`schema not found ${ref}`);
    v = ((d: unknown) => fn(d) as boolean) as Validator;
    (v as any).errors = () => fn.errors;
    cache.set(ref, v);
  }
  return v;
}
export const lastErrors = (v: Validator) => JSON.stringify((v as any).errors?.() ?? []);

export interface Operation {
  operationId: string;
  method: string;
  path: string;
  pathRegex: RegExp;
  paramNames: string[];
  requestSchema?: Json;
  /** required header parameter names (lowercased) */
  requiredHeaders: string[];
  responses: Record<string, Json>;
  isRootServer: boolean;
}

export const operations: Operation[] = [];
for (const [path, item] of Object.entries<Json>(spec.paths)) {
  for (const method of ['get', 'post', 'put', 'delete']) {
    const op = item[method];
    if (!op) continue;
    const paramNames: string[] = [];
    const rx = path.replace(/\{(\w+)\}/g, (_m, n) => {
      paramNames.push(n);
      return '([^/]+)';
    });
    const isRootServer = item.servers?.[0]?.url === '/';
    const requiredHeaders = (op.parameters ?? [])
      .map((p: Json) => deref(p))
      .filter((p: Json) => p.in === 'header' && p.required)
      .map((p: Json) => String(p.name).toLowerCase());
    operations.push({
      operationId: op.operationId,
      method: method.toUpperCase(),
      path,
      pathRegex: new RegExp(`^${isRootServer ? '' : '/v1'}${rx}$`),
      paramNames,
      requestSchema: op.requestBody?.content?.['application/json']?.schema,
      requiredHeaders,
      responses: op.responses,
      isRootServer,
    });
  }
}

export function matchOperation(method: string, pathname: string): { op: Operation; params: Record<string, string> } | undefined {
  for (const op of operations) {
    if (op.method !== method) continue;
    const m = op.pathRegex.exec(pathname);
    if (m) return { op, params: Object.fromEntries(op.paramNames.map((n, i) => [n, decodeURIComponent(m[i + 1]!)])) };
  }
  return undefined;
}

/** Schema node for a response (status) of an operation, or undefined (e.g. 204). */
export function responseSchema(op: Operation, status: number): Json | undefined {
  const r = op.responses[String(status)] ?? op.responses['default'];
  if (!r) return undefined;
  return deref(r).content?.['application/json']?.schema;
}
export function hasResponse(op: Operation, status: number): boolean {
  return String(status) in op.responses || 'default' in op.responses;
}
