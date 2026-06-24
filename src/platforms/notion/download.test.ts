import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test'

import { downloadBlockFile, downloadDeps } from './download'

const BLOCK_ID = '380e56d2-11e0-80a3-97a7-f1614dbf3a61'

function blockResponse(value: Record<string, unknown>) {
  return { recordMap: { block: { [BLOCK_ID]: { role: 'editor', value } } } }
}

describe('downloadBlockFile', () => {
  let originalFetch: typeof downloadDeps.fetch
  let originalInternalRequest: typeof downloadDeps.internalRequest
  let originalWriteFileSync: typeof downloadDeps.writeFileSync
  let written: { path: string; bytes: number } | null

  beforeEach(() => {
    // Avoid touching the OS keychain during tests.
    process.env.NOTION_FILE_TOKEN = 'test-file-token'
    originalFetch = downloadDeps.fetch
    originalInternalRequest = downloadDeps.internalRequest
    originalWriteFileSync = downloadDeps.writeFileSync
    written = null
    downloadDeps.writeFileSync = mock((path: string, data: Buffer) => {
      written = { path: String(path), bytes: (data as Buffer).length }
    }) as unknown as typeof downloadDeps.writeFileSync
  })

  afterEach(() => {
    downloadDeps.fetch = originalFetch
    downloadDeps.internalRequest = originalInternalRequest
    downloadDeps.writeFileSync = originalWriteFileSync
    delete process.env.NOTION_FILE_TOKEN
  })

  test('downloads a file block via signed URL with the file_token cookie', async () => {
    downloadDeps.internalRequest = mock((_token: string, endpoint: string) => {
      if (endpoint === 'syncRecordValues') {
        return Promise.resolve(
          blockResponse({
            id: BLOCK_ID,
            type: 'file',
            parent_table: 'block',
            space_id: 'space-1',
            properties: { source: [['attachment:fid:doc.pdf']], title: [['doc.pdf']] },
          }),
        )
      }
      if (endpoint === 'getSignedFileUrls') {
        return Promise.resolve({ signedUrls: ['https://file.notion.so/f/f/space-1/fid/doc.pdf?signature=abc'] })
      }
      throw new Error(`unexpected endpoint ${endpoint}`)
    }) as unknown as typeof downloadDeps.internalRequest

    downloadDeps.fetch = mock((url: string, init: { headers: Record<string, string> }) => {
      expect(url).toContain('file.notion.so')
      expect(init.headers.cookie).toContain('token_v2=tok')
      expect(init.headers.cookie).toContain('file_token=test-file-token')
      return Promise.resolve(
        new Response(new Uint8Array([1, 2, 3, 4]), { headers: { 'content-type': 'application/pdf' } }),
      )
    }) as unknown as typeof downloadDeps.fetch

    const result = await downloadBlockFile('tok', { blockId: BLOCK_ID, output: '/tmp/out-dir/' })

    expect(result.via).toBe('signed')
    expect(result.bytes).toBe(4)
    expect(result.contentType).toBe('application/pdf')
    expect(result.path.endsWith('doc.pdf')).toBe(true)
    expect(written?.path.endsWith('doc.pdf')).toBe(true)
  })

  test('falls back to the proxy when no signed URL is returned', async () => {
    downloadDeps.internalRequest = mock((_token: string, endpoint: string) => {
      if (endpoint === 'syncRecordValues') {
        return Promise.resolve(
          blockResponse({
            id: BLOCK_ID,
            type: 'image',
            parent_table: 'block',
            space_id: 'space-1',
            properties: { source: [['attachment:fid:image.png']], title: [['image.png']] },
          }),
        )
      }
      return Promise.resolve({ signedUrls: [] })
    }) as unknown as typeof downloadDeps.internalRequest

    downloadDeps.fetch = mock((url: string) => {
      expect(url).toContain('www.notion.so/image/')
      return Promise.resolve(new Response(new Uint8Array([9, 9]), { headers: { 'content-type': 'image/png' } }))
    }) as unknown as typeof downloadDeps.fetch

    const result = await downloadBlockFile('tok', { blockId: BLOCK_ID })

    expect(result.via).toBe('proxy')
    expect(result.bytes).toBe(2)
  })

  test('throws a clear error when the block has no downloadable file', async () => {
    downloadDeps.internalRequest = mock(() =>
      Promise.resolve(blockResponse({ id: BLOCK_ID, type: 'text', space_id: 'space-1', properties: {} })),
    ) as unknown as typeof downloadDeps.internalRequest
    downloadDeps.fetch = mock(() => Promise.resolve(new Response('x'))) as unknown as typeof downloadDeps.fetch

    await expect(downloadBlockFile('tok', { blockId: BLOCK_ID })).rejects.toThrow('no downloadable file')
  })
})
