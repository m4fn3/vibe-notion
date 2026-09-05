import fs from 'node:fs'
import path from 'node:path'

import { internalRequest } from './client'
import { resolveSpaceId } from './commands/helpers'
import { TokenExtractor } from './token-extractor'

type BlockRecord = {
  value?: Record<string, unknown>
  role?: string
}

type SyncRecordValuesResponse = {
  recordMap: {
    block: Record<string, BlockRecord>
  }
}

type SignedUrlsResponse = {
  signedUrls?: string[]
}

type PermissionRecord = {
  id: string
  table: string
  spaceId: string
}

export type DownloadResult = {
  id: string
  path: string
  bytes: number
  source: string
  contentType?: string
  via: 'signed' | 'proxy' | 'raw'
}

export const downloadDeps = {
  fetch: globalThis.fetch,
  internalRequest,
  writeFileSync: fs.writeFileSync,
  statSync: fs.statSync,
}

const NOTION_IMAGE_PROXY = 'https://www.notion.so/image/'

const CONTENT_TYPE_EXTENSIONS: Record<string, string> = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
  'image/webp': '.webp',
  'image/svg+xml': '.svg',
  'application/pdf': '.pdf',
  'application/zip': '.zip',
}

// Notion stores rich-text-like properties as [[ "value" ]]. Both `source`
// (the file URL) and `title` (the original filename) use this shape.
function firstPropertyString(prop: unknown): string | undefined {
  if (Array.isArray(prop) && Array.isArray(prop[0]) && typeof prop[0][0] === 'string') {
    return prop[0][0]
  }
  return undefined
}

// Mirrors block.ts unwrapBlockRecord: a record is sometimes
// { role, value } and sometimes { value: { role, value } }.
function unwrapBlock(record: BlockRecord | undefined): Record<string, unknown> | undefined {
  if (!record?.value) return undefined
  const outer = record.value
  if (typeof outer.role === 'string' && outer.value !== undefined) {
    return outer.value as Record<string, unknown>
  }
  return outer
}

async function fetchBlock(tokenV2: string, blockId: string): Promise<Record<string, unknown>> {
  const response = (await downloadDeps.internalRequest(tokenV2, 'syncRecordValues', {
    requests: [{ pointer: { table: 'block', id: blockId }, version: -1 }],
  })) as SyncRecordValuesResponse

  const blockMap = response.recordMap.block
  const block = unwrapBlock(blockMap[blockId]) ?? unwrapBlock(Object.values(blockMap)[0])
  if (!block) {
    throw new Error(`Block not found: ${blockId}`)
  }
  return block
}

async function getSignedUrl(tokenV2: string, source: string, record: PermissionRecord): Promise<string | undefined> {
  const response = (await downloadDeps.internalRequest(tokenV2, 'getSignedFileUrls', {
    urls: [{ url: source, permissionRecord: record }],
  })) as SignedUrlsResponse
  return response.signedUrls?.[0]
}

// Notion can serve files through a same-origin proxy that authenticates via the
// token_v2 cookie. Used as a fallback when a signed URL can't be obtained.
function buildProxyUrl(source: string, record: PermissionRecord): string {
  const query = `?table=${record.table}&id=${record.id}&spaceId=${record.spaceId}`
  if (source.startsWith(NOTION_IMAGE_PROXY)) {
    return source.includes('?') ? source : source + query
  }
  return NOTION_IMAGE_PROXY + encodeURIComponent(source) + query
}

// file.notion.so (and the notion.so proxies) authenticate file downloads via
// cookies, not the URL signature alone: token_v2 establishes the session and
// file_token authorizes file access — without file_token, file.notion.so 403s.
let cachedFileToken: string | null | undefined

// Notion mints file_token from token_v2 alone: any /api/v3 call answers with a
// `Set-Cookie: file_token=...`. This keeps downloads working on machines with no
// Notion desktop app (headless servers), where the cookie DB doesn't exist.
export async function fetchFileTokenOverHttp(tokenV2: string): Promise<string | null> {
  try {
    const response = await downloadDeps.fetch('https://www.notion.so/api/v3/loadUserContent', {
      method: 'POST',
      headers: { cookie: `token_v2=${tokenV2}`, 'content-type': 'application/json' },
      body: '{}',
    })
    const setCookie =
      typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [response.headers.get('set-cookie') ?? '']
    for (const cookie of setCookie) {
      const match = /(?:^|;\s*)file_token=([^;]+)/.exec(cookie)
      if (match) {
        return match[1]
      }
    }
  } catch {
    // fall through — download still attempts token_v2-only and proxy paths
  }
  return null
}

async function resolveFileToken(tokenV2: string): Promise<string | undefined> {
  if (cachedFileToken !== undefined) {
    return cachedFileToken ?? undefined
  }
  const fromEnv = process.env.NOTION_FILE_TOKEN
  if (fromEnv) {
    cachedFileToken = fromEnv
    return fromEnv
  }
  try {
    cachedFileToken = await new TokenExtractor().getFileToken()
  } catch {
    cachedFileToken = null
  }
  if (!cachedFileToken) {
    cachedFileToken = await fetchFileTokenOverHttp(tokenV2)
  }
  return cachedFileToken ?? undefined
}

async function httpGet(
  url: string,
  tokenV2: string,
  fileToken?: string,
): Promise<{ buffer: Buffer; contentType?: string }> {
  const headers: Record<string, string> = {}
  // Signed S3 URLs are self-authenticating; notion.so hosts need session cookies.
  if (new URL(url).host.endsWith('notion.so')) {
    headers.cookie = fileToken ? `token_v2=${tokenV2}; file_token=${fileToken}` : `token_v2=${tokenV2}`
  }
  const response = await downloadDeps.fetch(url, { headers })
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url.split('?')[0]}`)
  }
  const buffer = Buffer.from(await response.arrayBuffer())
  return { buffer, contentType: response.headers.get('content-type') ?? undefined }
}

function basenameFromUrl(source: string): string | undefined {
  // attachment:{fileId}:{filename}
  if (source.startsWith('attachment:')) {
    const parts = source.split(':')
    return parts.length >= 3 ? parts.slice(2).join(':') : undefined
  }
  try {
    const pathname = new URL(source).pathname
    const last = pathname.split('/').filter(Boolean).pop()
    return last ? decodeURIComponent(last) : undefined
  } catch {
    return undefined
  }
}

function resolveOutputPath(
  output: string | undefined,
  blockId: string,
  title: string | undefined,
  source: string,
  contentType: string | undefined,
): string {
  const ext = (contentType && CONTENT_TYPE_EXTENSIONS[contentType.split(';')[0].trim()]) ?? ''
  const fileName = title || basenameFromUrl(source) || `${blockId}${ext}`

  if (!output) return fileName

  let isDir = output.endsWith(path.sep)
  if (!isDir) {
    try {
      isDir = downloadDeps.statSync(output).isDirectory()
    } catch {
      isDir = false
    }
  }
  return isDir ? path.join(output, fileName) : output
}

export async function downloadBlockFile(
  tokenV2: string,
  args: { blockId: string; output?: string },
): Promise<DownloadResult> {
  const block = await fetchBlock(tokenV2, args.blockId)
  const properties = block.properties as Record<string, unknown> | undefined
  const source = firstPropertyString(properties?.source)
  if (!source) {
    throw new Error(
      `Block ${args.blockId} (type=${String(block.type)}) has no downloadable file (no properties.source)`,
    )
  }

  const spaceId = (block.space_id as string) ?? (await resolveSpaceId(tokenV2, args.blockId))
  const record: PermissionRecord = {
    id: args.blockId,
    table: (block.parent_table as string) ?? 'block',
    spaceId,
  }
  const title = firstPropertyString(properties?.title)
  const fileToken = await resolveFileToken(tokenV2)

  const attempts: Array<{ via: DownloadResult['via']; run: () => Promise<{ buffer: Buffer; contentType?: string }> }> =
    [
      {
        via: 'signed',
        run: async () => {
          const signed = await getSignedUrl(tokenV2, source, record)
          if (!signed) throw new Error('no signed URL returned')
          return httpGet(signed, tokenV2, fileToken)
        },
      },
      { via: 'proxy', run: () => httpGet(buildProxyUrl(source, record), tokenV2, fileToken) },
    ]
  if (/^https?:\/\//.test(source)) {
    attempts.push({ via: 'raw', run: () => httpGet(source, tokenV2, fileToken) })
  }

  let lastError: Error | undefined
  for (const attempt of attempts) {
    try {
      const { buffer, contentType } = await attempt.run()
      const outputPath = resolveOutputPath(args.output, args.blockId, title, source, contentType)
      downloadDeps.writeFileSync(outputPath, buffer)
      return {
        id: args.blockId,
        path: path.resolve(outputPath),
        bytes: buffer.length,
        source,
        contentType,
        via: attempt.via,
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))
    }
  }

  throw new Error(`Failed to download block ${args.blockId}: ${lastError?.message ?? 'unknown error'}`)
}
