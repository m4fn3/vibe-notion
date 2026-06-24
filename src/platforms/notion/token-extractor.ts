import { execSync } from 'node:child_process'
import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { copyFileSync, existsSync, readFileSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)

const TOKEN_REGEX = /v\d+(%3A|:)[A-Za-z0-9_.%-]+/
const UUID_REGEX = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/

// CBC decryption may produce padding garbage before the actual value.
// Try known patterns first (token, UUID), fall back to raw string.
function extractValueFromDecrypted(decrypted: string): string {
  const tokenMatch = decrypted.match(TOKEN_REGEX)
  if (tokenMatch) return tokenMatch[0]

  const uuidMatch = decrypted.match(UUID_REGEX)
  if (uuidMatch) return uuidMatch[0]

  return decrypted
}

type CookieRow = {
  name: string
  value?: string
  encrypted_value?: Uint8Array | Buffer
  last_access_utc?: number
} | null

type ExtractedTokenCandidate = {
  extracted: ExtractedToken
  lastAccessUtc: number
}

type BetterSqlite3Database = {
  prepare(sql: string): {
    get(...params: unknown[]): unknown
    all(...params: unknown[]): unknown[]
  }
  close(): void
}

type BetterSqlite3Constructor = {
  new (path: string, options?: Record<string, unknown>): BetterSqlite3Database
}

export interface ExtractedToken {
  token_v2: string
  user_id?: string
  user_ids?: string[]
  accounts?: Array<{
    token_v2: string
    user_id?: string
    user_ids?: string[]
  }>
}

export class TokenExtractor {
  private platform: NodeJS.Platform
  private notionDir: string
  private debug: boolean
  private cachedMasterKey: Buffer | null | undefined = undefined
  private extractionErrors: string[] = []

  constructor(platform?: NodeJS.Platform, notionDir?: string, options?: { debug?: boolean }) {
    this.platform = platform ?? process.platform
    this.notionDir = notionDir ?? this.getNotionDir()
    this.debug = options?.debug ?? false
  }

  getErrors(): string[] {
    return [...this.extractionErrors]
  }

  getNotionDir(): string {
    const candidates = this.getNotionDirCandidates()
    return candidates.find((candidate) => existsSync(candidate)) ?? candidates[0]
  }

  async extract(): Promise<ExtractedToken | null> {
    if (!existsSync(this.notionDir)) {
      const message = this.getMissingNotionDirMessage()
      throw new Error(message)
    }

    const [firstCandidate] = await this.extractAll()
    return firstCandidate ?? null
  }

  async extractAll(): Promise<ExtractedToken[]> {
    if (!existsSync(this.notionDir)) {
      const message = this.getMissingNotionDirMessage()
      throw new Error(message)
    }

    return this.extractCookiesFromSQLite()
  }

  tryDecryptCookie(encrypted: Buffer): string | null {
    if (encrypted.length > 3 && encrypted.subarray(0, 3).toString() === 'v10') {
      if (this.platform === 'win32') {
        return this.decryptV10CookieWindows(encrypted)
      }
      return this.decryptV10Cookie(encrypted)
    }

    const plaintext = encrypted.toString('utf8')
    if (/^v\d+(%3A|:)/.test(plaintext)) {
      return plaintext
    }

    // Windows pre-v80: DPAPI applied directly (no version prefix)
    if (this.platform === 'win32' && encrypted.length > 0) {
      const decrypted = this.decryptDpapi(encrypted)
      if (decrypted) {
        return decrypted.toString('utf8')
      }
    }

    return null
  }

  decryptV10Cookie(encrypted: Buffer): string | null {
    try {
      const key = this.getDerivedKey()
      if (!key) {
        this.extractionErrors.push('decryptV10Cookie: failed to derive decryption key')
        return null
      }

      const ciphertext = encrypted.subarray(3)
      const iv = Buffer.alloc(16, ' ')
      const decipher = createDecipheriv('aes-128-cbc', key, iv)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
    } catch (error) {
      this.extractionErrors.push(`decryptV10Cookie: ${(error as Error).message}`)
      return null
    }
  }

  decryptV10CookieWindows(encrypted: Buffer): string | null {
    try {
      const masterKey = this.getWindowsMasterKey()
      if (!masterKey) {
        const decrypted = this.decryptDpapi(encrypted.subarray(3))
        if (!decrypted) return null
        return decrypted.toString('utf8')
      }

      const nonce = encrypted.subarray(3, 3 + 12)
      const ciphertextWithTag = encrypted.subarray(3 + 12)
      const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16)
      const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16)

      const decipher = createDecipheriv('aes-256-gcm', masterKey, nonce)
      decipher.setAuthTag(tag)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
    } catch (error) {
      this.extractionErrors.push(`decryptV10CookieWindows: ${(error as Error).message}`)
      return null
    }
  }

  getWindowsMasterKey(): Buffer | null {
    if (this.cachedMasterKey !== undefined) {
      return this.cachedMasterKey
    }

    try {
      const localStatePath = join(this.notionDir, 'Local State')
      if (!existsSync(localStatePath)) {
        this.cachedMasterKey = null
        return null
      }

      const localState = JSON.parse(readFileSync(localStatePath, 'utf8')) as {
        os_crypt?: { encrypted_key?: string }
      }
      const encryptedKeyB64 = localState?.os_crypt?.encrypted_key
      if (!encryptedKeyB64) {
        this.cachedMasterKey = null
        return null
      }

      const encryptedKey = Buffer.from(encryptedKeyB64, 'base64')
      if (encryptedKey.subarray(0, 5).toString() !== 'DPAPI') {
        this.cachedMasterKey = null
        return null
      }

      this.cachedMasterKey = this.decryptDpapi(encryptedKey.subarray(5))
      return this.cachedMasterKey
    } catch (error) {
      this.extractionErrors.push(`getWindowsMasterKey: ${(error as Error).message}`)
      this.cachedMasterKey = null
      return null
    }
  }

  decryptDpapi(encrypted: Buffer): Buffer | null {
    if (this.platform !== 'win32') {
      return null
    }

    try {
      const b64Input = encrypted.toString('base64')
      const script = [
        'Add-Type -AssemblyName System.Security',
        `$d=[System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String("${b64Input}"),$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)`,
        '[Convert]::ToBase64String($d)',
      ].join(';')

      const encodedCommand = Buffer.from(script, 'utf16le').toString('base64')
      const result = execSync(`powershell -NoProfile -NonInteractive -EncodedCommand ${encodedCommand}`, {
        encoding: 'utf8',
        timeout: 10000,
      }).trim()

      return Buffer.from(result, 'base64')
    } catch (error) {
      this.extractionErrors.push(`decryptDpapi: ${(error as Error).message}`)
      return null
    }
  }

  getDerivedKey(): Buffer | null {
    if (this.platform === 'linux') {
      return pbkdf2Sync('peanuts', 'saltysalt', 1, 16, 'sha1')
    }

    if (this.platform === 'win32') {
      return null
    }

    if (this.platform !== 'darwin') {
      return null
    }

    try {
      let password: string
      try {
        password = execSync('security find-generic-password -s "Notion Safe Storage" -w 2>/dev/null', {
          encoding: 'utf8',
        }).trim()
      } catch {
        password = execSync('security find-generic-password -ga "Notion" -s "Notion Safe Storage" -w 2>/dev/null', {
          encoding: 'utf8',
        }).trim()
      }

      return pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1')
    } catch (error) {
      this.extractionErrors.push(`getDerivedKey: ${(error as Error).message}`)
      return null
    }
  }

  private getCookiePaths(): string[] {
    return [
      join(this.notionDir, 'Partitions', 'notion', 'Network', 'Cookies'),
      join(this.notionDir, 'Partitions', 'notion', 'Cookies'),
      join(this.notionDir, 'Network', 'Cookies'),
      join(this.notionDir, 'Cookies'),
    ]
  }

  // Reads the `file_token` cookie, required to download file blocks from
  // file.notion.so (token_v2 alone yields 403 there). Returns the value from
  // the most recently accessed matching cookie, or null if unavailable.
  async getFileToken(): Promise<string | null> {
    if (!existsSync(this.notionDir)) {
      return null
    }

    const sql = `SELECT name, value, encrypted_value, last_access_utc FROM cookies WHERE name = 'file_token' AND host_key LIKE '%notion%' ORDER BY last_access_utc DESC`
    let best: { value: string; lastAccess: number } | null = null

    for (const dbPath of this.getCookiePaths()) {
      if (!existsSync(dbPath)) {
        continue
      }
      let rows: CookieRow[]
      try {
        rows = this.copyAndQueryRows(dbPath, sql)
      } catch (error) {
        this.extractionErrors.push(`getFileToken: ${(error as Error).message}`)
        continue
      }
      for (const row of rows) {
        if (!row || row.name !== 'file_token') {
          continue
        }
        const raw = this.resolveCookieValue(row)
        if (!raw) {
          continue
        }
        const value = extractValueFromDecrypted(raw)
        const lastAccess = row.last_access_utc ?? 0
        if (!best || lastAccess > best.lastAccess) {
          best = { value, lastAccess }
        }
      }
    }

    return best?.value ?? null
  }

  private async extractCookiesFromSQLite(): Promise<ExtractedToken[]> {
    const cookiePaths = this.getCookiePaths()

    const candidatesByToken = new Map<string, ExtractedTokenCandidate>()

    for (const dbPath of cookiePaths) {
      const exists = existsSync(dbPath)
      if (this.debug) {
        console.error(`[debug] Cookie path candidate: ${dbPath} (exists: ${exists})`)
      }
      if (!exists) {
        continue
      }

      const extractedCandidates = this.readTokensFromDb(dbPath)
      if (this.debug) {
        console.error(
          `[debug] Cookie DB ${dbPath}: ${extractedCandidates.length > 0 ? `${extractedCandidates.length} token_v2 candidates found` : 'token_v2 not found'}`,
        )
      }

      for (const extracted of extractedCandidates) {
        const existing = candidatesByToken.get(extracted.extracted.token_v2)
        if (!existing || extracted.lastAccessUtc > existing.lastAccessUtc) {
          candidatesByToken.set(extracted.extracted.token_v2, extracted)
        }
      }
    }

    const candidates = [...candidatesByToken.values()]
    candidates.sort((left, right) => right.lastAccessUtc - left.lastAccessUtc)

    return candidates.map((candidate) => candidate.extracted)
  }

  protected getNotionDirCandidates(): string[] {
    switch (this.platform) {
      case 'darwin':
        return [
          join(homedir(), 'Library', 'Application Support', 'Notion'),
          join(homedir(), 'Library', 'Containers', 'notion.id', 'Data', 'Library', 'Application Support', 'Notion'),
          join(homedir(), 'Library', 'Containers', 'com.notion.id', 'Data', 'Library', 'Application Support', 'Notion'),
        ]
      case 'linux':
        return [join(homedir(), '.config', 'Notion')]
      case 'win32': {
        const appData = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')
        return [join(appData, 'Notion')]
      }
      default:
        throw new Error(`Unsupported platform: ${this.platform}`)
    }
  }

  private getMissingNotionDirMessage(): string {
    const candidates = this.getNotionDirCandidates()
    if (candidates.length === 1 || !candidates.includes(this.notionDir)) {
      return `Notion directory not found: ${this.notionDir}`
    }

    return `Notion directory not found: ${this.notionDir} (checked: ${candidates.join(', ')})`
  }

  private readTokensFromDb(dbPath: string): ExtractedTokenCandidate[] {
    const sql = `SELECT name, value, encrypted_value, last_access_utc FROM cookies WHERE name IN ('token_v2', 'notion_user_id', 'notion_users') AND host_key LIKE '%notion%' ORDER BY last_access_utc DESC`
    const rows = this.copyAndQueryRows(dbPath, sql)
    return this.buildCandidatesFromRows(rows)
  }

  // Copies the (possibly locked) cookie DB to a temp file and runs a read-only
  // query, working under both Bun and Node. Shared by token and file_token reads.
  private copyAndQueryRows(dbPath: string, sql: string): CookieRow[] {
    const tempDbPath = join(tmpdir(), `notion-cookies-${Date.now()}-${Math.random().toString(36).slice(2)}.db`)

    try {
      copyFileSync(dbPath, tempDbPath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EBUSY') {
        throw new Error(
          'Failed to read Notion cookies. The Notion app is currently running and locking the cookie database. ' +
            'Quit the Notion app completely and try again.',
        )
      }
      this.extractionErrors.push(`copyAndQueryRows: failed to copy cookie DB ${dbPath}: ${(error as Error).message}`)
      return []
    }

    try {
      let rows: CookieRow[]

      if (typeof globalThis.Bun !== 'undefined') {
        const { Database } = require('bun:sqlite')
        const db = new Database(tempDbPath, { readonly: true })
        rows = db.query(sql).all() as CookieRow[]
        db.close()
      } else {
        let Database: BetterSqlite3Constructor
        try {
          Database = require('better-sqlite3')
        } catch {
          throw new Error('better-sqlite3 is required for Node.js. Install it with: npm install better-sqlite3')
        }
        const db = new Database(tempDbPath, { readonly: true })
        rows = db.prepare(sql).all() as CookieRow[]
        db.close()
      }

      return rows
    } catch (error) {
      if (error instanceof Error && error.message.includes('better-sqlite3')) {
        throw error
      }
      this.extractionErrors.push(`copyAndQueryRows: ${(error as Error).message}`)
      return []
    } finally {
      try {
        rmSync(tempDbPath, { force: true })
      } catch {
        // Best-effort cleanup — temp file may already be removed
      }
    }
  }

  private buildCandidatesFromRows(rows: CookieRow[]): ExtractedTokenCandidate[] {
    const normalizedRows = rows.filter((row): row is NonNullable<CookieRow> => row !== null)
    const tokenAnchors = normalizedRows
      .map((row, index) => ({ row, index }))
      .filter(({ row }) => row.name === 'token_v2')

    const candidates: Array<ExtractedTokenCandidate & { tokenIndex: number }> = []
    const candidateIndexByTokenIndex = new Map<number, number>()

    tokenAnchors.forEach(({ row, index }) => {
      const rawToken = this.resolveCookieValue(row)
      if (!rawToken) {
        return
      }

      const candidateIndex = candidates.length
      candidates.push({
        extracted: {
          token_v2: extractValueFromDecrypted(rawToken),
        },
        lastAccessUtc: row.last_access_utc ?? 0,
        tokenIndex: index,
      })
      candidateIndexByTokenIndex.set(index, candidateIndex)
    })

    const chooseCandidateIndex = (rowIndex: number, rowLastAccessUtc: number): number | null => {
      let newerTokenAnchorIndex = -1
      for (let tokenAnchorIndex = 0; tokenAnchorIndex < tokenAnchors.length; tokenAnchorIndex++) {
        if (tokenAnchors[tokenAnchorIndex].index < rowIndex) {
          newerTokenAnchorIndex = tokenAnchorIndex
        }
      }
      const olderTokenAnchorIndex = tokenAnchors.findIndex((tokenAnchor) => tokenAnchor.index > rowIndex)

      if (newerTokenAnchorIndex === -1 && olderTokenAnchorIndex === -1) {
        return null
      }

      const newerTokenAnchor = newerTokenAnchorIndex === -1 ? null : tokenAnchors[newerTokenAnchorIndex]
      const olderTokenAnchor = olderTokenAnchorIndex === -1 ? null : tokenAnchors[olderTokenAnchorIndex]
      const newerCandidateIndex = newerTokenAnchor
        ? (candidateIndexByTokenIndex.get(newerTokenAnchor.index) ?? null)
        : null
      const olderCandidateIndex = olderTokenAnchor
        ? (candidateIndexByTokenIndex.get(olderTokenAnchor.index) ?? null)
        : null
      const newerDistance = newerTokenAnchor
        ? Math.abs((newerTokenAnchor.row.last_access_utc ?? 0) - rowLastAccessUtc)
        : Number.POSITIVE_INFINITY
      const olderDistance = olderTokenAnchor
        ? Math.abs((olderTokenAnchor.row.last_access_utc ?? 0) - rowLastAccessUtc)
        : Number.POSITIVE_INFINITY

      if (newerCandidateIndex === null && olderCandidateIndex === null) {
        return null
      }

      if (newerTokenAnchorIndex === -1) {
        return olderCandidateIndex
      }

      if (olderTokenAnchorIndex === -1) {
        return newerCandidateIndex
      }

      if (newerCandidateIndex === null) {
        return olderDistance < newerDistance ? olderCandidateIndex : null
      }

      if (olderCandidateIndex === null) {
        return newerDistance < olderDistance ? newerCandidateIndex : null
      }

      return newerDistance <= olderDistance ? newerCandidateIndex : olderCandidateIndex
    }

    normalizedRows.forEach((row, rowIndex) => {
      if (row.name === 'token_v2') {
        return
      }

      const candidateIndex = chooseCandidateIndex(rowIndex, row.last_access_utc ?? 0)
      if (candidateIndex === null) {
        return
      }

      const candidate = candidates[candidateIndex]
      if (row.name === 'notion_user_id' && !candidate.extracted.user_id) {
        const rawUserId = this.resolveCookieValue(row)
        const userId = rawUserId ? extractValueFromDecrypted(rawUserId) : null
        if (userId) {
          candidate.extracted.user_id = userId
        }
      }

      if (row.name === 'notion_users' && !candidate.extracted.user_ids) {
        const userIds = this.parseUserIds(row)
        if (userIds.length > 0) {
          candidate.extracted.user_ids = userIds
        }
      }
    })

    return candidates.map(({ tokenIndex: _tokenIndex, ...candidate }) => candidate)
  }

  private parseUserIds(row: CookieRow): string[] {
    const raw = this.resolveCookieValue(row)
    if (!raw) return []

    try {
      const parsed = JSON.parse(raw) as unknown
      if (Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')) {
        return parsed
      }
    } catch {
      // Not valid JSON — try extracting JSON array from decrypted value (may have padding prefix)
      const match = raw.match(/\[.*\]/)
      if (match) {
        try {
          const parsed = JSON.parse(match[0]) as unknown
          if (Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')) {
            return parsed
          }
        } catch {
          // Substring also not valid JSON — fall through to return []
        }
      }
    }

    return []
  }

  private resolveCookieValue(row: CookieRow): string | null {
    if (!row) {
      return null
    }

    if (typeof row.value === 'string' && row.value.length > 0) {
      return row.value
    }

    if (row.encrypted_value && row.encrypted_value.length > 0) {
      return this.tryDecryptCookie(Buffer.from(row.encrypted_value))
    }

    return null
  }
}
