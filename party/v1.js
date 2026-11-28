/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *    This script hands the name and address of your own profile    *
 *     in the WebFluid "users" Additive to other parts of your      *
 *      application: it decrypts them on your device and sends      *
 *      them nowhere. To keep your application transparent and      *
 *       secure, you should not edit or change its content by       *
 *      yourself. Additionally we highly recommend to add the       *
 *     "peering" Additive to your application and to not remove     *
 *             the "users" Additive's peering features.             *
 *                                                                  *
 ********************************************************************/

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/party\.js$/, "")

const ID = "users"
const VERSION = 1
const TIMEOUT = 10000

const READY = "ready"
const LOCKED = "locked"
const UNAVAILABLE = "unavailable"


export class PartyError extends Error {
    constructor(code) {
        super(code)
        this.name = "PartyError"
        this.code = code
    }
}

function fail(code) {
    throw new PartyError(code)
}

function loaded() {
    const found = window.wf?.e2ee?.providers?.[ID]
    if (found) return Promise.resolve(found)
    return new Promise(resolve => {
        const timer = setTimeout(() => resolve(null), TIMEOUT)
        const listener = event => {
            if (event.detail?.id !== ID) return
            clearTimeout(timer)
            window.removeEventListener("e2ee:provider", listener)
            resolve(window.wf?.e2ee?.providers?.[ID] ?? null)
        }
        window.addEventListener("e2ee:provider", listener)
    })
}

async function profile() {
    const response = await fetch(`${PREFIX}/api/v1/profile`, { credentials: "same-origin" }).catch(() => null)
    if (!response) fail("CLIENT_UNAVAILABLE")
    if (response.status === 401 || response.status === 403) fail("CLIENT_LOCKED")
    if (!response.ok) fail("CLIENT_UNAVAILABLE")
    return response.json().catch(() => fail("CLIENT_UNAVAILABLE"))
}

async function opened(crypto, value) {
    if (typeof value !== "string" || !value) return ""
    if (!crypto?.isEnvelope?.(value)) return value
    try {
        return await crypto.decrypt(value)
    } catch {
        fail(crypto.ready() ? "CLIENT_UNAVAILABLE" : "CLIENT_LOCKED")
    }
}


export async function state() {
    const provider = await loaded()
    if (!provider) return UNAVAILABLE
    try {
        const current = await provider.state()
        return [READY, LOCKED].includes(current) ? current : UNAVAILABLE
    } catch {
        return UNAVAILABLE
    }
}

export async function party() {
    const data = await profile()
    let crypto = null
    if (data?.encrypted) {
        const current = await state()
        if (current === LOCKED) fail("CLIENT_LOCKED")
        if (current !== READY) fail("CLIENT_UNAVAILABLE")
        crypto = window.wf?.adt?.users?.e2ee
        if (!crypto?.ready()) fail("CLIENT_LOCKED")
    }
    const address = data?.address && typeof data.address === "object" ? data.address : null
    const found = { kind: "person", given_name: await opened(crypto, data?.first_name),
                    family_name: await opened(crypto, data?.last_name) }
    if (address) found.address = {
        line1: await opened(crypto, address.line_1), line2: await opened(crypto, address.line_2),
        postal_code: await opened(crypto, address.zip), city: await opened(crypto, address.city),
        state: await opened(crypto, address.state), country: await opened(crypto, address.country)
    }
    return found
}


const provider = Object.freeze({ id: ID, version: VERSION, state, party })
window.wf ??= {}
window.wf.parties ??= { providers: {} }
window.wf.parties.providers ??= {}
try {
    Object.defineProperty(window.wf.parties.providers, ID, { value: provider, enumerable: true, writable: false,
                                                             configurable: false })
} catch {}
window.dispatchEvent(new CustomEvent("parties:provider", { detail: { id: ID } }))
