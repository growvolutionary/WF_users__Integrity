/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *    This script offers the account key of the WebFluid "users"    *
 *     Additive as an end-to-end encryption provider: it wraps      *
 *    and unwraps the keys of other parts of your application on    *
 *    your device, bound to the context they name. To keep your     *
 *    application transparent and secure, you should not edit or    *
 *      change its content by yourself. Additionally we highly      *
 *         recommend to add the "peering" Additive to your          *
 *       application and to not remove the "users" Additive's       *
 *                        peering features.                         *
 *                                                                  *
 ********************************************************************/

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/e2ee-provider\.js$/, "")

const ID = "users"
const VERSION = 1
const SCHEME = "users-k1"
const KIND = "e2ee"
const ENVELOPE = "e1."
const KEY_LENGTH = 32
const MAX_WRAPPED = 2048
const MAX_KEY_REF = 256
const CONTEXT = ["key_ref", "object", "purpose", "recipient", "v"]
const TEXTS = ["object", "recipient", "key_ref", "purpose"]
const TIMEOUT = 10000

const READY = "ready"
const LOCKED = "locked"
const UNAVAILABLE = "unavailable"

let account = null
let verified = false
let checking = null


export class E2eeError extends Error {
    constructor(code) {
        super(code)
        this.name = "E2eeError"
        this.code = code
    }
}

function fail(code) {
    throw new E2eeError(code)
}

function loaded(name, event) {
    const found = window.wf?.adt?.users?.[name]
    if (found) return Promise.resolve(found)
    return new Promise(resolve => {
        const timer = setTimeout(() => resolve(null), TIMEOUT)
        window.addEventListener(event, () => {
            clearTimeout(timer)
            resolve(window.wf?.adt?.users?.[name] ?? null)
        }, { once: true })
    })
}

function secure() {
    return !!globalThis.isSecureContext && !!globalThis.crypto?.subtle
}

function encode(bytes) {
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function decode(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) fail("ENVELOPE_INVALID")
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

function checked(context) {
    if (!context || typeof context !== "object" || Array.isArray(context)) fail("ENVELOPE_INVALID")
    const keys = Object.keys(context).sort()
    if (keys.length !== CONTEXT.length || keys.some((key, index) => key !== CONTEXT[index])) fail("ENVELOPE_INVALID")
    if (context.v !== VERSION) fail("ENVELOPE_INVALID")
    if (TEXTS.some(key => typeof context[key] !== "string" || !context[key])) fail("ENVELOPE_INVALID")
    if (context.key_ref.length > MAX_KEY_REF) fail("ENVELOPE_INVALID")
    return { v: VERSION, object: context.object, recipient: context.recipient, key_ref: context.key_ref,
             purpose: context.purpose }
}

async function read(path) {
    const response = await fetch(`${PREFIX}/api/v1/${path}`, { credentials: "same-origin" }).catch(() => null)
    if (!response?.ok) return null
    return response.json().catch(() => null)
}

async function owned(crypto) {
    const profile = await read("profile")
    if (!profile?.encrypted || profile.id !== account) return false
    const sealed = [profile.first_name, profile.last_name].find(value => crypto.isEnvelope(value))
    if (!sealed) return false
    return crypto.decrypt(sealed).then(() => true, () => false)
}

async function unlock(crypto, current) {
    if (current.share && current.binding) {
        const { share, binding, user_id: user } = current
        return crypto.unlock({ share, binding, user }).catch(() => false)
    }
    if (current.device) return false
    const unlocker = await loaded("session", "users:session")
    return unlocker ? unlocker.unlockVault(current.user_id).catch(() => false) : false
}

async function inspect() {
    verified = false
    if (!secure()) return UNAVAILABLE
    const crypto = await loaded("e2ee", "users:e2ee")
    if (!crypto || !await crypto.supported().catch(() => false)) return UNAVAILABLE
    const current = await read("mobile/session")
    account = Number.isSafeInteger(current?.user_id) ? current.user_id : null
    if (account === null) return LOCKED
    if (current.encrypted === false) return UNAVAILABLE
    if (!crypto.ready()) await unlock(crypto, current)
    if (!crypto.ready()) return LOCKED
    verified = await owned(crypto)
    return verified ? READY : LOCKED
}

async function usable() {
    const crypto = window.wf?.adt?.users?.e2ee
    if (crypto?.ready() && verified) return crypto
    const current = await state()
    if (current === UNAVAILABLE) fail("CLIENT_UNAVAILABLE")
    if (current !== READY) fail("CLIENT_LOCKED")
    return window.wf.adt.users.e2ee
}

function bound(context) {
    if (context.recipient !== `account:${account}`) fail("WRONG_RECIPIENT")
}

function same(crypto, left, right) {
    try {
        return crypto.canonical(left) === crypto.canonical(right)
    } catch {
        return false
    }
}


export function state() {
    checking ??= inspect().catch(() => UNAVAILABLE).finally(() => { checking = null })
    return checking
}

export async function wrap(context, key) {
    const scoped = checked(context)
    if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) fail("ENVELOPE_INVALID")
    const crypto = await usable()
    bound(scoped)
    let wrapped
    try {
        wrapped = await crypto.encrypt(crypto.canonical({ ctx: scoped, key: encode(key), t: KIND, v: VERSION }))
    } catch {
        fail(crypto.ready() ? "ENVELOPE_INVALID" : "CLIENT_LOCKED")
    }
    if (wrapped.length > MAX_WRAPPED) fail("ENVELOPE_INVALID")
    return wrapped
}

export async function unwrap(context, wrapped) {
    const expected = checked(context)
    if (typeof wrapped !== "string" || wrapped.length > MAX_WRAPPED || !wrapped.startsWith(ENVELOPE)) {
        fail("ENVELOPE_INVALID")
    }
    const crypto = await usable()
    bound(expected)
    let data
    try {
        data = JSON.parse(await crypto.decrypt(wrapped))
    } catch {
        fail(crypto.ready() ? "ENVELOPE_INVALID" : "CLIENT_LOCKED")
    }
    if (!data || typeof data !== "object" || Array.isArray(data) || Object.keys(data).length !== 4
        || data.t !== KIND || data.v !== VERSION || typeof data.key !== "string" || !("ctx" in data)) {
        fail("ENVELOPE_INVALID")
    }
    const key = decode(data.key)
    if (key.length !== KEY_LENGTH) fail("ENVELOPE_INVALID")
    if (!same(crypto, data.ctx, expected)) {
        key.fill(0)
        fail("ENVELOPE_MISMATCH")
    }
    return key
}


window.addEventListener("users:e2ee-reset", () => {
    account = null
    verified = false
})

const provider = Object.freeze({ id: ID, version: VERSION, schemes: Object.freeze([SCHEME]), state, wrap, unwrap })
window.wf.e2ee ??= { providers: {} }
window.wf.e2ee.providers ??= {}
try {
    Object.defineProperty(window.wf.e2ee.providers, ID, { value: provider, enumerable: true, writable: false,
                                                         configurable: false })
} catch {}
window.dispatchEvent(new CustomEvent("e2ee:provider", { detail: { id: ID } }))
