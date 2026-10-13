# Static e2ee.js and session.js integrity

This repository contains the version history of the two static JavaScript files the `users` Additive
serves for its end-to-end encryption — `e2ee.js`, which holds all cryptography, and `session.js`, which
unlocks the account key for a session — with their original source and correlating hashes.

## Contents

| Path              | Meaning                                                                                       |
|-------------------|-----------------------------------------------------------------------------------------------|
| `e2ee/v<N>.js`    | The published source of every version of `static/js/e2ee.js` (artifact `users_e2ee`).         |
| `session/v<N>.js` | The published source of every version of `static/js/session.js` (artifact `users_session`).   |
| `generate.py`     | Computes the SHA-256 of every version and writes `manifest.json` (and `<artifact>/hashes/`).  |
| `manifest.json`   | The public reference, format 2: per artifact one entry per version (`version`, `file`, `sha256`, `size`) and `latest`. |
| `.gitattributes`  | Pins `e2ee/*.js` and `session/*.js` to LF, so a checkout on any platform hashes to the same value. |

`generate.py` hashes the content as stored in git: CRLF line endings count as LF, so a clone made
before `.gitattributes` existed still reproduces the published value. The output is deterministic and
carries no timestamps; running it twice produces identical files. The `hashes/` folders are a local
by-product and not committed, `manifest.json` is.

```bash
python generate.py
```

The `users` Additive clones this repository, runs `generate.py` exactly once per integrity run as a
subprocess of its own interpreter, recomputes every hash itself and only reports versions whose hashes
it could reproduce. A failing or non-reproducible run is reported as "reference unavailable", never as
a fresh result. Peers fetch `manifest.json` from this repository directly (not through the host) and
compare it with the script the host actually serves.

## What the hashes prove

A matching hash proves that a host serves the bytes published here — nothing more. Every QR code a
browser shows for a handshake or a link carries the hashes and versions of both scripts; the mobile SDK
accepts them when the host's peers confirm them, or — without peers — when its release pins them (a map
from version to hash per script). It does not prove that the published code is free of bugs, and it
cannot prove what a host does on its server side.
A host that serves an older version than `latest` is reported as *outdated*, one that serves bytes
that match no version as a *reference mismatch*.

## Manual Trust Check

The account area of an application runs its own trust check before it shows anything confidential.
That check runs inside the page the host delivered — a compromised host could manipulate it. The
snippet below lets technically experienced users ask the peers of a host directly, from a page the
host does not control.

**Get the snippet from here, not from the application.** Read it on GitHub
(`https://github.com/growvolutionary/WF_users__Integrity`), compare it with the version in the
repository history, and only run code you have read. It is short on purpose.

1. Open a new, empty tab (`about:blank`). Do not run it on the application's own page: that page's
   scripts could have replaced `fetch` or `crypto`.
2. Open the developer tools with `CTRL + SHIFT + I` (`CMD + OPTION + I` on macOS) and switch to
   **Console**.
3. Edit `HOST` (and, if you know peers from an independent source, `EXTRA_PEERS`), paste the block and
   press Enter. Some browsers ask you to type `allow pasting` first.

```js
(async () => {
    const HOST = "https://example.org"
    const EXTRA_PEERS = []
    const ARTIFACTS = ["users_e2ee", "users_session"]

    const HOST_API = "/peering/api/v1"
    const PEER_API = "/api/v1"
    const api = (origin, base, path) => fetch(`${origin}${base}${path}`, {
        credentials: "omit", cache: "no-store", redirect: "error"
    }).then(response => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
    const b64 = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")
        + "=".repeat((4 - text.length % 4) % 4)), char => char.charCodeAt(0))
    const canonical = value => value === null ? "null"
        : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
        : typeof value === "object" ? `{${Object.keys(value).sort()
            .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
        : JSON.stringify(value)
    const verify = async (key, context, payload, signature) => {
        const publicKey = await crypto.subtle.importKey("raw", b64(key), { name: "Ed25519" }, false, ["verify"])
        const message = new TextEncoder().encode(`${context}\n${canonical(payload)}`)
        return crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64(signature), message)
    }
    const safe = promise => promise.then(value => value, error => ({ error: error.message }))

    const hosts = {}
    for (const artifact of ARTIFACTS) hosts[artifact] = await safe(api(HOST, HOST_API, `/hash?id=${artifact}`))
    const listed = await safe(api(HOST, HOST_API, "/peers"))
    const peers = [...new Set([...(listed.peers || []).map(peer => peer.url), ...EXTRA_PEERS])]
        .filter(url => /^https:\/\//.test(url || ""))

    const rows = []
    for (const url of peers) {
        const [node, trust, checkpoint, ...hashes] = await Promise.all([
            safe(api(url, PEER_API, "/node")), safe(api(url, PEER_API, "/trust")),
            safe(api(url, PEER_API, "/checkpoints/latest")),
            ...ARTIFACTS.map(artifact => safe(api(url, PEER_API, `/hash?id=${artifact}`)))
        ])
        const statement = node.statement || {}
        const identity = !node.error && statement.url === url
            && await verify(statement.key, "wf-peering-node-v1", statement, node.signature || "").catch(() => false)
        const signed = identity && !trust.error && trust.key === statement.key
            && await verify(trust.key, "wf-trust-v1", { node: trust.node, key: trust.key, report: trust.report }, trust.signature)
                .catch(() => false)
        const assessment = signed ? trust.report.host : {}
        rows.push({
            peer: url,
            reachable: !node.error,
            signed_identity: identity,
            peers_this_host: statement.host === HOST,
            score: assessment.target === HOST ? assessment.score : null,
            level: assessment.target === HOST ? assessment.level : null,
            basis: assessment.target === HOST ? assessment.basis : null,
            observed: Object.fromEntries(ARTIFACTS.map((artifact, index) => [artifact, hashes[index].observation?.observed ?? null])),
            status: Object.fromEntries(ARTIFACTS.map((artifact, index) => [artifact, hashes[index].observation?.status ?? null])),
            checkpoint: checkpoint.error ? null : `${checkpoint.day} ${checkpoint.status}`,
            ledger_size: checkpoint.content?.ledger?.size ?? null,
            ledger_root: checkpoint.content?.ledger?.root ?? null
        })
    }

    for (const artifact of ARTIFACTS) {
        const host = hosts[artifact]
        console.log(`Host claim for ${artifact}:`, host.error ?? `${host.hash} (served ${host.served_version}, latest ${host.latest_version})`)
    }
    console.table(rows)

    const findings = []
    const confirmed = rows.filter(row => row.signed_identity && row.peers_this_host)
    if (!confirmed.length) findings.push("No peer of this host could be verified: the result is UNCLEAR, not good.")
    for (const row of confirmed) {
        for (const artifact of ARTIFACTS) {
            const claimed = hosts[artifact].hash
            if (claimed && row.observed[artifact] && row.observed[artifact] !== claimed) {
                findings.push(`${row.peer} observed a different ${artifact} than the host claims.`)
            }
            if (["served-mismatch", "reference-mismatch", "outdated"].includes(row.status[artifact])) {
                findings.push(`${row.peer} reports for ${artifact}: ${row.status[artifact]}.`)
            }
        }
        if (row.level === "critical" || row.level === "warning") findings.push(`${row.peer} rates the host: ${row.level}.`)
    }
    const roots = {}
    for (const row of confirmed.filter(row => row.ledger_root)) (roots[row.ledger_size] ??= new Set()).add(row.ledger_root)
    for (const [size, set] of Object.entries(roots)) {
        if (set.size > 1) findings.push(`Peers disagree about the ledger of size ${size}: possible split view.`)
    }
    console.log(findings.length ? findings.join("\n") : "No deviation found among the verified peers.")
    console.log("Limits: the host chose which peers to list; peers may share an operator; a browser cannot "
        + "inspect TLS certificates or DNS; matching values prove agreement, not correctness.")
})()
```

What the snippet does — and what it does not:

- It only sends `GET` requests without credentials to the public peering APIs: the host's under
  `/peering/api/v1` (served by its peering Additive), every peer's under `/api/v1` (the peering app). It reads no cookies,
  passwords, local keys, session data or storage, uses no `eval` and loads no further code.
- It checks the Ed25519 signatures of every peer's identity and trust report, compares the hash of both
  scripts each peer observed with the hashes the host claims, and compares the peers' latest checkpoint
  roots.
- The browser verifies TLS for every `https` request, but a script cannot inspect certificates, DNS
  records or the operator behind a peer. Peers check those themselves; their results appear as their
  signed claims.
- The list of peers comes from the host. A compromised host can leave peers out. Add peers you know
  from an independent source to `EXTRA_PEERS`.
- Peers that do not answer or block cross-origin requests are listed as unreachable. Missing answers
  make the result unclear — they are neither a confirmation nor proof of manipulation.
- To check the scripts you are actually served, download them (`<host>/users/static/js/e2ee.js` and
  `<host>/users/static/js/session.js`) and compare `sha256sum e2ee.js session.js` with `manifest.json` in
  this repository.

A clean result means that the peers you reached agree with each other and with the host's claims.
It is not a guarantee that the host is uncompromised.

## License

The code of this repository is a public integrity promise that belongs to
the WebFluid "users" Additive. The code is licensed as [ARR (All rights reserved)](LICENSE).
