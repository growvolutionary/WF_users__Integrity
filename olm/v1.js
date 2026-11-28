/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *          This script holds the device identity of this           *
 *       browser for the WebFluid "users" Additive, receives        *
 *         the end-to-end encrypted messages sent to it and         *
 *       hands each one to the part of your application that        *
 *       expects it. To keep your application transparent and       *
 *       secure, you should not edit or change its content by       *
 *      yourself. Additionally we highly recommend to add the       *
 *        "peering" Additive to your application and to not         *
 *         remove the "users" Additive's peering features.          *
 *                                                                  *
 ********************************************************************/

import * as vodozemac from "../vendor/vodozemac/0.1.0/vodozemac_bg.js"

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/olm\.js$/, "")
const OLM = `${PREFIX}/api/v1/olm`
const PROTOCOL = 1
const WASM_SHA256 = "5b3a606864bbcfe31f4e91f12e73b659c494f6d13c36cb6e1ec94dce992410fd"
const LOADED = Symbol.for("wf.users.vodozemac")
const BIND = "users-olm-bind-v1"
const SIGNING = "users-olm-signing-v1"
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
const MIN_KEYS = 20
const KEY_BATCH = 40
const PEER_SESSIONS = 4
const SEEN_LIMIT = 2000
const LIST_TTL = 60000
const WAITING_LIMIT = 256
const WAITING_TTL = 30 * 24 * 3600 * 1000
const LEASE = 120000
const RETRY_BASE = 5000
const RETRY_MAX = 600000
const POLL = 30000
const OPEN_BACKOFF = 60000
const TYPE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/
const DATABASE = "users-olm"
const STORE = "state"
const CHANNEL = "users-olm"
const MAILBOX = "users_olm:message"
const PEERING_HEALTH = "/peering/api/health"
const HEALTH_TIMEOUT = 4000
const HEALTH_LIFETIME = 10 * 60 * 1000
const PEER_TIMEOUT = 6000
const TIMEOUT = 10000

const subtle = globalThis.crypto.subtle
const encoder = new TextEncoder()


export class OlmError extends Error {
    constructor(code, status = 0) {
        super(code)
        this.name = "OlmError"
        this.code = code
        this.status = status
    }
}

function concat(...parts) {
    const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

export function b64(bytes) {
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/=+$/, "")
}

export function fromB64(text) {
    const value = String(text).replace(/-/g, "+").replace(/_/g, "/")
    const binary = atob(value + "=".repeat((4 - value.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

export function b64url(bytes) {
    return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_")
}

export function randomId(length = 16) {
    return b64url(globalThis.crypto.getRandomValues(new Uint8Array(length)))
}

async function hex(bytes) {
    return Array.from(new Uint8Array(await subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("")
}

async function digest16(bytes) {
    return b64url(new Uint8Array(await subtle.digest("SHA-256", bytes)).slice(0, 16))
}

export const fingerprint = key => digest16(fromB64(key))
export const keyFingerprint = key => digest16(fromB64(key))

export async function verify(publicKey, context, payload, signature, canonical) {
    try {
        const key = await subtle.importKey("raw", fromB64(publicKey), { name: "Ed25519" }, false, ["verify"])
        return await subtle.verify({ name: "Ed25519" }, key, fromB64(signature), encoder.encode(`${context}\n${canonical(payload)}`))
    } catch {
        return false
    }
}

export async function signer(seed, canonical) {
    const pkcs8 = concat(PKCS8_ED25519, seed)
    const exportable = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"])
    const publicKey = (await subtle.exportKey("jwk", exportable)).x
    const key = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"])
    return {
        publicKey,
        async sign(context, payload) {
            const signature = await subtle.sign({ name: "Ed25519" }, key, encoder.encode(`${context}\n${canonical(payload)}`))
            return b64url(new Uint8Array(signature))
        }
    }
}

export async function verifyDevice(record, canonical) {
    const binding = record?.binding ?? {}
    if (binding.ctx !== BIND || binding.account !== record.account || binding.device !== record.device
        || binding.curve25519 !== record.curve25519 || binding.ed25519 !== record.ed25519
        || typeof record.device_key !== "string") return false
    if (record.kind === "browser") {
        const signing = record.signing
        const anchor = signing?.binding ?? {}
        if (binding.kind !== "browser" || anchor.ctx !== SIGNING || anchor.account !== record.account
            || anchor.signing !== signing.signing || anchor.device !== await fingerprint(record.device_key)) return false
        if (await keyFingerprint(record.ed25519) !== record.device) return false
        return await verify(record.device_key, SIGNING, anchor, signing.signature, canonical)
            && await verify(signing.signing, BIND, binding, record.signature, canonical)
    }
    if (record.kind !== "app" || "kind" in binding) return false
    if (await fingerprint(record.device_key) !== record.device) return false
    return verify(record.device_key, BIND, binding, record.signature, canonical)
}

export function typeOf(plaintext) {
    try {
        const data = JSON.parse(plaintext)
        return typeof data?.t === "string" && TYPE.test(data.t) ? data.t : null
    } catch {
        return null
    }
}

export function load(wasm) {
    globalThis[LOADED] ??= (async () => {
        const bytes = wasm ?? await fetch(new URL("../vendor/vodozemac/0.1.0/vodozemac_bg.wasm", SOURCE),
            { credentials: "same-origin" }).then(response => {
            if (!response.ok) throw new OlmError("CRYPTO_UNAVAILABLE")
            return response.arrayBuffer()
        })
        if (await hex(bytes) !== WASM_SHA256) throw new OlmError("CRYPTO_MISMATCH")
        const { instance } = await WebAssembly.instantiate(bytes, { "./vodozemac_bg.js": vodozemac })
        vodozemac.__wbg_set_wasm(instance.exports)
        instance.exports.__wbindgen_start()
        return vodozemac
    })().catch(error => {
        delete globalThis[LOADED]
        throw error
    })
    return globalThis[LOADED]
}

export function idbStore(database = DATABASE, store = STORE) {
    const open = () => new Promise((resolve, reject) => {
        const request = indexedDB.open(database, 1)
        request.onupgradeneeded = () => request.result.createObjectStore(store)
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
    const run = async (mode, work) => {
        const db = await open()
        try {
            return await new Promise((resolve, reject) => {
                const transaction = db.transaction(store, mode)
                const request = work(transaction.objectStore(store))
                transaction.oncomplete = () => resolve(request?.result)
                transaction.onerror = () => reject(transaction.error)
                transaction.onabort = () => reject(transaction.error)
            })
        } finally {
            db.close()
        }
    }
    return {
        get: key => run("readonly", objects => objects.get(key)),
        set: (key, value) => run("readwrite", objects => objects.put(value, key)).then(() => undefined),
        del: key => run("readwrite", objects => objects.delete(key)).then(() => undefined)
    }
}

function exclusive(ctx, work) {
    const locks = ctx.locks === undefined ? globalThis.navigator?.locks : ctx.locks
    if (!locks?.request) return work()
    return locks.request(`users-olm:${ctx.user}`, { mode: "exclusive" }, work)
}

function usable(record, ctx) {
    return record?.v === PROTOCOL && record.account === ctx.account && typeof record.key === "string"
        && typeof record.olm === "string"
}

function person(record) {
    return { account: record.account, device: record.device, ed25519: record.ed25519, kind: record.kind ?? "app",
             device_key: record.device_key ?? null }
}

function retryAt(attempts) {
    return Date.now() + Math.min(RETRY_BASE * 2 ** Math.max(0, attempts - 1), RETRY_MAX)
}


export class UsersDevice {
    constructor(ctx) {
        this.ctx = ctx
        this.vz = ctx.vz
        this.tab = randomId(8)
        this.olm = null
        this.pickleKey = null
        this.sealedKey = null
        this.sessions = new Map()
        this.seen = []
        this.pins = {}
        this.notices = {}
        this.waiting = []
        this.rev = null
        this.device = null
        this.identity = null
        this.lists = new Map()
        this.signingCache = null
        this.created = 0
        this.handlers = new Map()
        this.queue = Promise.resolve()
        this.dispatching = null
        this.again = false
        this.timer = null
        this.closed = false
    }

    static storeKey(user) {
        return `device:${user}`
    }

    static async open(ctx) {
        const device = new UsersDevice(ctx)
        const retire = await exclusive(ctx, () => device.boot())
        if (retire) await device.retire(retire).catch(() => null)
        return device
    }

    get key() {
        return UsersDevice.storeKey(this.ctx.user)
    }

    async boot() {
        let record = await this.ctx.store.get(this.key).catch(() => null)
        let retire = usable(this.ctx.adopt, this.ctx) ? this.ctx.adopt : null
        if (!usable(record, this.ctx) && retire) {
            record = retire
            retire = null
        }
        if (usable(record, this.ctx)) {
            try {
                await this.hydrate(record)
                if (record === this.ctx.adopt) await this.save()
                return retire
            } catch {
                await this.ctx.store.del(this.key).catch(() => null)
            }
        }
        this.pickleKey = globalThis.crypto.getRandomValues(new Uint8Array(32))
        this.sealedKey = await this.ctx.sealer.encrypt(b64url(this.pickleKey))
        this.olm = new this.vz.Account()
        this.identity = this.olm.ed25519_key
        this.device = await keyFingerprint(this.identity)
        await this.save()
        return retire
    }

    async hydrate(record) {
        const pickleKey = fromB64(await this.ctx.sealer.decrypt(record.key))
        const olm = this.vz.Account.from_pickle(record.olm, pickleKey)
        const sessions = new Map(Object.entries(record.sessions ?? {}).map(([peer, items]) =>
            [peer, items.map(item => this.vz.Session.from_pickle(item, pickleKey))]))
        const waiting = typeof record.waiting === "string" ? JSON.parse(await this.ctx.sealer.decrypt(record.waiting)) : []
        this.olm?.free()
        for (const items of this.sessions.values()) for (const item of items) item.free()
        this.olm = olm
        this.pickleKey = pickleKey
        this.sealedKey = record.key
        this.sessions = sessions
        this.seen = Array.isArray(record.seen) ? record.seen : []
        this.pins = record.pins ?? {}
        this.notices = record.notices ?? {}
        this.waiting = Array.isArray(waiting) ? waiting : []
        this.rev = record.rev ?? null
        this.identity = olm.ed25519_key
        this.device = await keyFingerprint(this.identity)
    }

    async retire(record) {
        const pickleKey = fromB64(await this.ctx.sealer.decrypt(record.key))
        const olm = this.vz.Account.from_pickle(record.olm, pickleKey)
        const device = await keyFingerprint(olm.ed25519_key)
        olm.free()
        if (device === this.device) return
        await this.ctx.http.del(`${OLM}/devices/${encodeURIComponent(device)}`).catch(() => null)
    }

    async refresh() {
        if (this.closed) throw new OlmError("DEVICE_CLOSED")
        const record = await this.ctx.store.get(this.key).catch(() => null)
        if (!usable(record, this.ctx)) {
            this.close()
            throw new OlmError("DEVICE_GONE")
        }
        if (record.rev !== this.rev) await this.hydrate(record)
    }

    serial(work) {
        const step = () => exclusive(this.ctx, async () => {
            await this.refresh()
            return work()
        })
        const run = this.queue.then(step, step)
        this.queue = run.catch(() => null)
        return run
    }

    async save() {
        const rev = randomId(9)
        await this.ctx.store.set(this.key, {
            v: PROTOCOL, account: this.ctx.account, key: this.sealedKey, olm: this.olm.pickle(this.pickleKey),
            sessions: Object.fromEntries([...this.sessions].map(([peer, items]) => [peer, items.map(item => item.pickle(this.pickleKey))])),
            seen: this.seen.slice(-SEEN_LIMIT), pins: this.pins, notices: this.notices,
            waiting: this.waiting.length ? await this.ctx.sealer.encrypt(JSON.stringify(this.waiting)) : null, rev
        })
        this.rev = rev
    }

    self() {
        return { account: this.ctx.account, device: this.device, ed25519: this.identity }
    }

    async signing() {
        if (this.signingCache) return this.signingCache
        const data = await this.ctx.http.get(`${OLM}/signing`)
        if (!data?.current) throw new OlmError("SIGNING_KEY_STALE", 409)
        const created = await signer(fromB64(await this.ctx.sealer.decrypt(data.secret)), this.ctx.canonical)
        if (created.publicKey !== data.signing) throw new OlmError("SIGNING_KEY_MISMATCH", 409)
        return this.signingCache = created
    }

    unpublished() {
        const keys = this.olm.one_time_keys
        return keys instanceof Map ? Object.fromEntries(keys) : { ...(keys ?? {}) }
    }

    async publishNow() {
        const sign = await this.signing()
        const binding = {
            ctx: BIND, account: this.ctx.account, device: this.device, curve25519: this.olm.curve25519_key,
            ed25519: this.identity, kind: "browser", ts: Math.floor(Date.now() / 1000)
        }
        const signature = await sign.sign(BIND, binding)
        const post = async () => {
            const answer = await this.ctx.http.post(`${OLM}/keys`, { binding, signature, one_time_keys: this.unpublished() })
            this.olm.mark_keys_as_published()
            return answer
        }
        let answer = await post()
        if ((answer?.stored ?? 0) < MIN_KEYS) {
            this.olm.generate_one_time_keys(KEY_BATCH).free()
            answer = await post()
        }
        this.created = 0
        await this.save()
        return answer
    }

    publish() {
        return this.serial(() => this.publishNow())
    }

    claim(account, keys) {
        const query = new URLSearchParams({ exclude: this.device })
        if (keys) query.set("keys", keys.join(","))
        return this.ctx.http.post(`${OLM}/devices/${encodeURIComponent(account)}/claim?${query}`)
    }

    async trustNow(account, deviceKey) {
        if (typeof deviceKey !== "string" || !deviceKey) return false
        const verdict = this.ctx.verifyKey ? await this.ctx.verifyKey(account, deviceKey).catch(() => "unknown") : "unknown"
        if (verdict === "conflict") return false
        const pinned = this.pins[account]
        if (pinned !== deviceKey) {
            if (pinned) this.notices[account] = Date.now()
            this.pins[account] = deviceKey
            await this.save()
        }
        return true
    }

    notice(account) {
        return this.notices[account] ?? null
    }

    acknowledge(account) {
        return this.serial(async () => {
            if (!(account in this.notices)) return
            delete this.notices[account]
            await this.save()
        })
    }

    async accept(account, claim) {
        if (!claim || claim.account !== account || !await this.trustNow(account, claim.device_key)) return []
        const out = []
        for (const record of claim.devices ?? []) {
            if (record.account !== account || record.device === this.device || record.device_key !== claim.device_key) continue
            if (await verifyDevice(record, this.ctx.canonical)) out.push(record)
        }
        return out
    }

    async devicesNow(account, fresh = false) {
        const cached = this.lists.get(account)
        if (!fresh && cached && Date.now() - cached.at < LIST_TTL) return cached.devices
        const devices = await this.accept(account, await this.claim(account, []))
        this.lists.set(account, { at: Date.now(), devices })
        return devices
    }

    devices(account, fresh = false) {
        return this.serial(() => this.devicesNow(account, fresh))
    }

    address(record) {
        return `${record.account}/${record.device}`
    }

    async outbound(record) {
        const address = this.address(record)
        const sessions = this.sessions.get(address)
        if (sessions?.length) return sessions
        let key = record.one_time_key?.key
        if (!key) {
            const fresh = (await this.accept(record.account, await this.claim(record.account, [record.device])))
                .find(item => item.device === record.device && item.one_time_key?.key)
            if (!fresh || fresh.curve25519 !== record.curve25519) throw new OlmError("NO_ONE_TIME_KEY")
            key = fresh.one_time_key.key
        }
        const created = [this.olm.create_outbound_session(record.curve25519, key, this.vz.SessionConfigVersion.V1)]
        this.sessions.set(address, created)
        return created
    }

    async sendNow(record, plaintext) {
        if (record?.device === this.device && record?.account === this.ctx.account) throw new OlmError("OWN_DEVICE")
        if (!await verifyDevice(record, this.ctx.canonical) || !await this.trustNow(record.account, record.device_key)) {
            throw new OlmError("UNTRUSTED_BINDING")
        }
        const sessions = await this.outbound(record)
        const message = sessions[0].encrypt(plaintext)
        const type = message.message_type
        const body = b64(message.ciphertext)
        message.free()
        await this.save()
        const messageId = randomId(16)
        await this.ctx.http.post(`${OLM}/messages`, {
            account: record.account, device: record.device, message_id: messageId, type, body, sender: this.device
        })
        return messageId
    }

    sendTo(record, plaintext) {
        return this.serial(() => this.sendNow(record, plaintext))
    }

    send(account, plaintext, { fresh = true } = {}) {
        return this.serial(async () => {
            const devices = await this.devicesNow(account, fresh)
            if (!devices.length) throw new OlmError("NO_DEVICES")
            const sent = []
            for (const record of devices) {
                try {
                    await this.sendNow(record, plaintext)
                    sent.push(record.device)
                } catch (error) {
                    if (error?.code !== "NO_ONE_TIME_KEY" && error?.code !== "UNTRUSTED_BINDING" && error?.status !== 404) throw error
                }
            }
            if (!sent.length) throw new OlmError("UNDELIVERED")
            return sent
        })
    }

    decryptFrom(sender, type, body) {
        const address = this.address(sender)
        const sessions = this.sessions.get(address) ?? []
        const bytes = fromB64(body)
        for (let index = 0; index < sessions.length; index++) {
            const message = new this.vz.OlmMessage(type, bytes)
            try {
                const plaintext = sessions[index].decrypt(message)
                if (index) sessions.unshift(...sessions.splice(index, 1))
                return plaintext
            } catch {
                continue
            } finally {
                message.free()
            }
        }
        if (type !== 0) throw new OlmError("NO_MATCHING_SESSION")
        const message = new this.vz.OlmMessage(type, bytes)
        try {
            const created = this.olm.create_inbound_session(sender.curve25519, message)
            const plaintext = created.plaintext
            sessions.unshift(created.session)
            while (sessions.length > PEER_SESSIONS) sessions.pop().free()
            this.sessions.set(address, sessions)
            this.created += 1
            return plaintext
        } finally {
            message.free()
        }
    }

    expire(now = Date.now()) {
        this.waiting = this.waiting.filter(entry => now - entry.at < WAITING_TTL)
        if (this.waiting.length > WAITING_LIMIT) this.waiting = this.waiting.slice(-WAITING_LIMIT)
    }

    async receiveNow() {
        const data = await this.ctx.http.get(`${OLM}/messages?device=${encodeURIComponent(this.device)}`)
        const ids = []
        let stored = 0
        for (const item of data?.messages ?? []) {
            ids.push(item.id)
            const sender = item.sender
            const mark = `${sender?.account}/${sender?.device}#${item.message_id}`
            if (!sender || this.seen.includes(mark)) continue
            this.seen.push(mark)
            if (!await verifyDevice(sender, this.ctx.canonical) || !await this.trustNow(sender.account, sender.device_key)) continue
            let plaintext
            try {
                plaintext = this.decryptFrom(sender, item.type, item.body)
            } catch {
                continue
            }
            const type = typeOf(plaintext)
            if (!type) continue
            this.waiting.push({ id: mark, t: type, plaintext, sender: person(sender), at: Date.now(), attempts: 0, retry: 0,
                                lease: 0, owner: null })
            stored += 1
        }
        this.expire()
        if (this.seen.length > SEEN_LIMIT) this.seen = this.seen.slice(-SEEN_LIMIT)
        await this.save()
        if (ids.length) await this.ctx.http.post(`${OLM}/messages/ack`, { ids })
        if (this.created) await this.publishNow()
        if (stored) this.ctx.notify?.()
        return stored
    }

    async receive() {
        const received = await this.serial(() => this.receiveNow())
        const handled = await this.dispatch()
        return { received, handled }
    }

    register(type, handler) {
        if (typeof type !== "string" || !TYPE.test(type) || typeof handler !== "function") throw new OlmError("INVALID_TYPE")
        this.handlers.set(type, handler)
        void this.dispatch().catch(() => null)
        return () => {
            if (this.handlers.get(type) === handler) this.handlers.delete(type)
        }
    }

    pending(type = null) {
        return this.serial(async () => this.waiting.filter(entry => type === null || entry.t === type).length)
    }

    message(entry) {
        let data = null
        try {
            data = JSON.parse(entry.plaintext)
        } catch {
            data = null
        }
        return {
            id: entry.id, type: entry.t, data, plaintext: entry.plaintext, sender: { ...entry.sender },
            recipient: { account: this.ctx.account, device: this.device }, received: entry.at, attempts: entry.attempts
        }
    }

    dispatch() {
        if (this.dispatching) {
            this.again = true
            return this.dispatching
        }
        this.dispatching = (async () => {
            let handled = 0
            do {
                this.again = false
                handled += await this.dispatchOnce()
            } while (this.again)
            return handled
        })().finally(() => {
            this.dispatching = null
            this.plan()
        })
        return this.dispatching
    }

    async dispatchOnce() {
        if (!this.handlers.size || this.closed) return 0
        const now = Date.now()
        const picked = await this.serial(async () => {
            this.expire(now)
            const due = this.waiting.filter(entry => this.handlers.has(entry.t) && entry.retry <= now && entry.lease <= now)
            if (!due.length) return []
            for (const entry of due) {
                entry.lease = now + LEASE
                entry.owner = this.tab
            }
            await this.save()
            return due.map(entry => ({ ...entry, sender: { ...entry.sender } }))
        })
        if (!picked.length) return 0
        const results = []
        for (const entry of picked) {
            const handler = this.handlers.get(entry.t)
            if (!handler) {
                results.push([entry.id, null])
                continue
            }
            try {
                await handler(this.message(entry))
                results.push([entry.id, true])
            } catch {
                results.push([entry.id, false])
            }
        }
        await this.serial(async () => {
            for (const [id, done] of results) {
                const index = this.waiting.findIndex(entry => entry.id === id && entry.owner === this.tab)
                if (index < 0) continue
                const entry = this.waiting[index]
                if (done) {
                    this.waiting.splice(index, 1)
                    continue
                }
                entry.lease = 0
                entry.owner = null
                if (done === false) {
                    entry.attempts += 1
                    entry.retry = retryAt(entry.attempts)
                }
            }
            await this.save()
        })
        return results.filter(([, done]) => done).length
    }

    plan() {
        clearTimeout(this.timer)
        this.timer = null
        if (this.closed) return
        const now = Date.now()
        const next = Math.min(...this.waiting.filter(entry => this.handlers.has(entry.t) && Math.max(entry.retry, entry.lease) > now)
            .map(entry => Math.max(entry.retry, entry.lease)))
        if (!Number.isFinite(next)) return
        this.timer = setTimeout(() => void this.dispatch().catch(() => null), next - now + 50)
        this.timer?.unref?.()
    }

    close() {
        this.closed = true
        clearTimeout(this.timer)
        this.timer = null
    }

    async forget() {
        this.close()
        await this.ctx.http.del(`${OLM}/devices/${encodeURIComponent(this.device)}`).catch(() => null)
        await exclusive(this.ctx, () => this.ctx.store.del(this.key)).catch(() => null)
    }
}


const verdicts = new Map()
const offers = new Map()
const handlers = new Map()
let current = null
let opening = null
let failed = 0
let channel = null
let listening = false

async function probePeering() {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), HEALTH_TIMEOUT)
    try {
        const response = await fetch(new URL(PEERING_HEALTH, location.origin), {
            credentials: "same-origin", cache: "no-store", signal: controller.signal, redirect: "error"
        })
        if (response.status === 404 || response.status === 410) return "absent"
        if (!response.ok) return "unreachable"
        const health = await response.json().catch(() => null)
        return health?.status === "ok" ? "available" : "absent"
    } catch {
        return "unreachable"
    } finally {
        clearTimeout(timer)
    }
}

export function peeringOffered() {
    const origin = location.origin
    const known = offers.get(origin)
    if (known && (known.pending || Date.now() - known.at < HEALTH_LIFETIME)) return known.offer
    const entry = { at: Date.now(), pending: true, offer: null }
    entry.offer = probePeering().then(state => {
        entry.pending = false
        entry.at = Date.now()
        if (state === "unreachable" && offers.get(origin) === entry) offers.delete(origin)
        return state
    })
    offers.set(origin, entry)
    return entry.offer
}

function peeringVerifier() {
    const loaded = window.wf?.adt?.peering?.verifier
    if (loaded) return Promise.resolve(loaded)
    return new Promise(resolve => {
        const timer = setTimeout(() => resolve(null), PEER_TIMEOUT)
        window.addEventListener("peering:verifier", () => {
            clearTimeout(timer)
            resolve(window.wf.adt.peering.verifier)
        }, { once: true })
    })
}

export function verifyKey(account, deviceKey) {
    const key = `${location.origin}#${account}#${deviceKey}`
    let verdict = verdicts.get(key)
    if (!verdict) {
        let keep = true
        verdict = (async () => {
            const offered = await peeringOffered()
            if (offered !== "available") {
                keep = offered === "absent"
                return "unknown"
            }
            const verifier = await peeringVerifier()
            if (!verifier) {
                keep = false
                return "unknown"
            }
            const result = await verifier.account(account, deviceKey).catch(() => null)
            if (result?.status === "confirmed") return "confirmed"
            if (result?.status === "conflict") return "conflict"
            keep = !!result
            return "unknown"
        })().catch(() => {
            keep = false
            return "unknown"
        })
        verdicts.set(key, verdict)
        verdict.then(() => {
            if (!keep && verdicts.get(key) === verdict) verdicts.delete(key)
        })
    }
    return verdict
}

function waitFor(read, event) {
    const value = read()
    if (value) return Promise.resolve(value)
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new OlmError("CLIENT_UNAVAILABLE")), TIMEOUT)
        window.addEventListener(event, () => {
            clearTimeout(timer)
            const loaded = read()
            if (loaded) resolve(loaded)
            else reject(new OlmError("CLIENT_UNAVAILABLE"))
        }, { once: true })
    })
}

async function parse(response) {
    const data = await response.json().catch(() => null)
    if (!response.ok) throw new OlmError(typeof data?.detail === "string" ? data.detail : "UNKNOWN_ERROR", response.status)
    return data
}

function call(method, path, body) {
    const csrf = window.wf?.adt?.auth?.csrfFetch
    const options = {
        method, credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body)
    }
    return (csrf ? csrf(path, options) : fetch(path, options)).then(parse)
}

const http = {
    get: path => fetch(path, { credentials: "same-origin" }).then(parse),
    post: (path, body) => call("POST", path, body ?? {}),
    del: path => call("DELETE", path)
}

function announce() {
    channel?.postMessage({ kind: "waiting", user: current?.ctx.user ?? null })
}

function listen() {
    const Bus = window.wf?.ext?.events?.EventBus
    if (listening || !Bus) return
    listening = true
    const events = new Bus()
    void events.subscribe(MAILBOX).then(() => events.registerHandler(MAILBOX, data => {
        if (current && !current.closed && data?.device === current.device) void current.receive().catch(() => null)
    })).catch(() => {
        listening = false
    })
}

async function start(adopt) {
    if (!globalThis.isSecureContext || !subtle) throw new OlmError("INSECURE_CONTEXT")
    const e2ee = await waitFor(() => window.wf?.adt?.users?.e2ee, "users:e2ee")
    if (!await e2ee.supported() || typeof WebAssembly === "undefined") throw new OlmError("CLIENT_UNAVAILABLE")
    const session = await waitFor(() => window.wf?.adt?.users?.session, "users:session")
    const state = await session.unlock()
    if (!Number.isSafeInteger(state?.user_id)) throw new OlmError("UNAUTHENTICATED", 401)
    if (!state.device) throw new OlmError("MOBILE_NOT_ENROLLED", 400)
    if (!state.mode || !e2ee.ready()) throw new OlmError("CLIENT_LOCKED")
    const signing = await http.get(`${OLM}/signing`)
    if (typeof signing?.account !== "string") throw new OlmError("NO_SIGNING_KEY", 404)
    if (!signing.current) throw new OlmError("SIGNING_KEY_STALE", 409)
    const device = await UsersDevice.open({
        vz: await load(), http, store: idbStore(), user: state.user_id, account: signing.account, adopt,
        sealer: { encrypt: text => e2ee.encrypt(text), decrypt: envelope => e2ee.decrypt(envelope) },
        canonical: value => e2ee.canonical(value), verifyKey, notify: announce
    })
    await device.publish()
    for (const [type, handler] of handlers) device.register(type, handler)
    return device
}

export function open({ adopt = null, force = false } = {}) {
    if (current && !current.closed) {
        if (adopt && usable(adopt, current.ctx)) void current.retire(adopt).catch(() => null)
        return Promise.resolve(current)
    }
    if (!opening && !force && failed && Date.now() - failed < OPEN_BACKOFF && !adopt) {
        return Promise.reject(new OlmError("CLIENT_UNAVAILABLE"))
    }
    opening ??= start(adopt).then(device => {
        current = device
        failed = 0
        listen()
        return device
    }, error => {
        failed = Date.now()
        throw error instanceof OlmError ? error : new OlmError(error?.code ?? "CLIENT_UNAVAILABLE", error?.status ?? 0)
    }).finally(() => {
        opening = null
    })
    return opening
}

export function register(type, handler) {
    if (typeof type !== "string" || !TYPE.test(type) || typeof handler !== "function") throw new OlmError("INVALID_TYPE")
    handlers.set(type, handler)
    let undo = current && !current.closed ? current.register(type, handler) : null
    if (!undo) {
        open().then(device => {
            if (handlers.get(type) === handler) undo = device.register(type, handler)
        }).catch(() => null)
    }
    return () => {
        if (handlers.get(type) === handler) handlers.delete(type)
        undo?.()
    }
}

export async function receive() {
    return (await open()).receive()
}

export function reset() {
    current?.close()
    current = null
    failed = 0
}

function wake() {
    if (document.hidden || (!handlers.size && !current)) return
    void receive().catch(() => null)
}

if (typeof window !== "undefined") {
    channel = "BroadcastChannel" in globalThis ? new BroadcastChannel(CHANNEL) : null
    channel?.addEventListener("message", event => {
        if (event.data?.kind === "waiting" && current && event.data.user === current.ctx.user) {
            void current.dispatch().catch(() => null)
        }
    })
    window.addEventListener("users:e2ee-reset", reset)
    document.addEventListener("visibilitychange", wake)
    setInterval(wake, POLL)

    window.wf ??= {}
    window.wf.adt ??= {}
    window.wf.adt.users = {
        ...window.wf.adt.users,
        olm: {
            OlmError, UsersDevice, open, register, receive, reset, verifyKey, peeringOffered, verifyDevice, typeOf,
            get device() { return current && !current.closed ? current : null }
        }
    }
    window.dispatchEvent(new Event("users:olm"))
}
