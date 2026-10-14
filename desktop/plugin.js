import { Button, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { useEffect, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const ENABLE_COPY = 'Enable the CozyChat plugin in Hermes to pair your phone.'
const CSS = `
.cozychat-page{height:100%;overflow:auto;color:var(--ui-text-primary);font:inherit}
.cozychat-content{max-width:660px;margin:auto;padding:32px 24px 48px}
.cozychat-content h1{font-size:24px;line-height:1.25;font-weight:600;margin:0 0 12px}
.cozychat-content h2{font-size:16px;font-weight:600;margin:0 0 12px}
.cozychat-content p{line-height:1.5;max-width:65ch;margin:0 0 16px}
.cozychat-content section{margin-top:28px}
.cozychat-secondary{color:var(--ui-text-secondary)}
.cozychat-qr{display:block;width:min(100%,300px);height:auto;background:white;border-radius:8px}
.cozychat-countdown{margin-top:12px;font-variant-numeric:tabular-nums}
.cozychat-code{font:600 36px/1.4 var(--font-mono,monospace);letter-spacing:.08em;margin-bottom:16px}
.cozychat-actions{display:flex;gap:12px;flex-wrap:wrap}
.cozychat-content button{min-height:44px}
.cozychat-phones{list-style:none;margin:0;padding:0}
.cozychat-phone{display:flex;gap:8px 16px;flex-wrap:wrap;align-items:center;padding:12px 0;border-bottom:1px solid var(--ui-stroke-secondary)}
.cozychat-phone-name{flex:1 1 12ch;overflow-wrap:anywhere;min-width:0}
.cozychat-phone-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;margin-left:auto}
.cozychat-reachable{display:flex;gap:16px;align-items:center;justify-content:space-between;min-height:44px;cursor:pointer;line-height:1.5}
.cozychat-reachable input{width:22px;height:22px;flex-shrink:0;accent-color:var(--ui-accent);cursor:pointer}
.cozychat-link{display:block;margin-top:16px;max-width:100%;overflow-wrap:anywhere}
.cozychat-link textarea{display:block;margin-top:8px;width:100%;min-height:88px;padding:8px;color:var(--ui-text-primary);background:var(--ui-bg-base);border:1px solid var(--ui-stroke-secondary);border-radius:6px;font:inherit;resize:vertical}
.cozychat-loading{min-height:300px;background:var(--ui-bg-secondary);border-radius:8px}
.cozychat-content :focus-visible{outline:2px solid var(--ui-accent);outline-offset:3px}
@media(max-width:480px){.cozychat-content{padding:24px 16px}.cozychat-code{font-size:30px}}
`

function createController(ctx, changed, now = () => Date.now()) {
  let model = { state: null, qr: null, busy: false, error: null, disabled: false }
  let disposed = false
  let loading = false
  let remainingUntil = 0
  let actionError = null
  const cleanupCopy = "Phone removed. Notification cleanup could not finish. Try again."
  const publish = patch => {
    model = { ...model, ...patch }
    if (!disposed) changed(model)
  }
  const failure = (error, backendRequest = false) => {
    const status = error?.status ?? error?.statusCode ?? Number(error?.message?.match(/^(\d{3}):/)?.[1])
    let detail = error?.detail || error?.message || 'Hermes could not finish. Try again.'
    try { detail = JSON.parse(detail.slice(detail.indexOf('{'))).detail || detail } catch {}
    if (detail === 'Update Hermes to use CozyChat') {
      publish({ error: detail, disabled: true, qr: null })
    } else if ([401, 403].includes(status) || status === 404 && backendRequest || detail === ENABLE_COPY || !model.state) {
      publish({ error: ENABLE_COPY, disabled: true, qr: null })
    } else {
      actionError = detail
      publish({ error: detail, qr: null })
    }
  }
  async function read(automatic) {
    let requestedAt = now()
    let state = await ctx.rest('/pair/state')
    if (disposed) return
    if (state.update_required) {
      // D34: Hermes without its secret scope cannot serve credentials; publish no QR.
      publish({ state, qr: null, error: state.update_required, disabled: true })
      return
    }
    publish({ state, disabled: false, qr: state.window && !state.pending &&
      model.qr?.window_id === state.window.id ? model.qr : null })
    if (automatic && state.first_visit) {
      // The server makes this idempotent across windows, reloads and React's effect replay.
      requestedAt = now()
      publish({ busy: true })
      try {
        state = await ctx.rest('/pair/open', { method: 'POST', body: { automatic: true }, timeoutMs: 120000 })
      } finally { publish({ busy: false }) }
      if (disposed) return
    }
    let qr = model.qr
    if (!state.window || state.window.remaining <= 0 || state.pending) qr = null
    else if (qr?.window_id !== state.window.id) qr = await ctx.rest('/pair/qr')
    remainingUntil = state.window ? requestedAt + state.window.remaining * 1000 : 0
    if (state.push_cleanup_pending) actionError = cleanupCopy
    else if (actionError === cleanupCopy) actionError = null
    publish({ state, qr, error: actionError, disabled: false, cleanupPending: !!state.push_cleanup_pending })
  }
  return {
    async load(automatic = false) {
      if (loading || model.busy || disposed) return
      loading = true
      try { await read(automatic) } catch (error) { failure(error, true) }
      finally { loading = false }
    },
    async act(path, body = {}, method = 'POST') {
      if (model.busy || disposed) return
      actionError = null
      publish({ busy: true, error: null })
      try {
        const result = await ctx.rest(path, { method, body, timeoutMs: 120000 })
        if (result?.pending_cleanup) actionError = cleanupCopy
        await read(false)
      } catch (error) { failure(error) }
      finally { publish({ busy: false }) }
    },
    tick() {
      if (!model.state?.window) return
      const remaining = Math.max(0, Math.ceil((remainingUntil - now()) / 1000))
      publish({ state: { ...model.state, window: { ...model.state.window, remaining } },
        qr: remaining ? model.qr : null })
    },
    dispose() { disposed = true },
  }
}

function PairingView({ model, act }) {
  const { state, qr, busy, error, disabled } = model
  const button = (text, path, body, variant = 'secondary') => jsx(Button, {
    variant, disabled: busy, onClick: () => act(path, body), children: text,
  })
  const pending = state?.window?.remaining > 0 ? state.pending : null
  const remaining = state?.window?.remaining || 0
  const seconds = String(remaining % 60).padStart(2, '0')
  const contents = [jsx('h1', { children: 'CozyChat' })]
  if (disabled) contents.push(jsx('p', { role: 'status', children: ENABLE_COPY }))
  else {
    if (!state) contents.push(jsx('div', { className: 'cozychat-loading', role: 'status', 'aria-label': 'Starting phone setup' }))
    if (error) contents.push(jsx('p', { role: 'status', children: error }))
    if (model.cleanupPending) contents.push(button("Try again", "/push/cleanup", {}))
    if (state?.wsl_note) contents.push(jsx('p', { className: 'cozychat-secondary', children: state.wsl_note }))
    if (pending) {
      contents.push(jsxs('section', { 'aria-label': 'Confirm phone', children: [
        jsx('h2', { children: `Pair ${pending.phone_name}?` }),
        jsx('p', { children: 'Check that this code matches the one on your phone.' }),
        jsx('div', { className: 'cozychat-code', 'aria-label': `Pairing code ${pending.code}`, children: `${pending.code.slice(0, 3)} ${pending.code.slice(3)}` }),
        pending.decision ? jsx('p', { role: 'status', children: 'Finishing…' }) : jsxs('div', {
          className: 'cozychat-actions', children: [
            button('Approve', '/pair/approve', { id: pending.id }, 'default'),
            button('Refuse', '/pair/refuse', { id: pending.id }),
          ],
        }),
      ] }))
    } else if (qr && remaining > 0) {
      contents.push(jsxs('section', { 'aria-label': 'Scan to pair', children: [
        jsx('p', { children: 'Scan this with CozyChat on your phone. Your phone connects straight to this computer over your Wi-Fi, sealed end to end.' }),
        jsx('img', { className: 'cozychat-qr', src: qr.png, alt: 'Scan this code in CozyChat to pair your phone' }),
        jsx('p', { className: 'cozychat-countdown cozychat-secondary', children: `Code closes in ${Math.floor(remaining / 60)}:${seconds}` }),
        jsxs('details', { className: 'cozychat-link', children: [
          jsx('summary', { children: 'Use a pairing link instead' }),
          jsx('textarea', { readOnly: true, 'aria-label': 'Pairing link', value: qr.link, onFocus: event => event.target.select() }),
        ] }),
      ] }))
    } else if (state) {
      if (!state.phones.length) contents.push(jsx('p', { children: 'Connect your phone to the same Wi-Fi as this computer, then pair it with CozyChat.' }))
      contents.push(button(busy ? 'Starting…' : 'Pair a phone', '/pair/open', {}))
    }
    if (state?.phones.length) contents.push(jsxs('section', { children: [
      jsx('h2', { children: 'Paired phones' }),
      jsx('ul', { className: 'cozychat-phones', children: state.phones.map(phone => jsxs('li', {
        className: 'cozychat-phone', children: [jsx('span', { className: 'cozychat-phone-name', children: phone.name }),
          jsxs('div', { className: 'cozychat-phone-actions', children: [jsx(Button, {
            variant: 'destructive', disabled: busy, 'aria-label': `Remove ${phone.name}`,
            onClick: () => act(`/phones/${encodeURIComponent(phone.id)}`, {}, 'DELETE'), children: 'Remove',
          }), state.rotation?.available ? jsx(Button, {
            variant: 'secondary', disabled: busy || state.rotation.pending,
            'aria-label': `Remove ${phone.name} and rotate API key`,
            onClick: () => act(`/phones/${encodeURIComponent(phone.id)}`, { rotate: true }, 'DELETE'),
            children: 'Remove and rotate key',
          }) : null] })],
      }, phone.id)) }),
    ] }))
    if (state?.rotation?.available) contents.push(jsxs('section', { children: [
      jsx('h2', { children: 'API key' }),
      jsx('p', { className: 'cozychat-secondary', children: 'Rotating the key restarts Hermes after active chats finish. Other paired phones reconnect automatically.' }),
      state.rotation.pending ? jsx('p', { role: 'status', children: 'Waiting for Hermes to finish rotating the key…' })
        : button('Rotate API key', '/rotate', {}),
    ] }))
    if (state) contents.push(jsxs('section', { children: [
      jsxs('label', { className: 'cozychat-reachable', children: [
        jsx('span', { children: 'Keep reachable when Hermes Desktop is closed' }),
        jsx('input', { type: 'checkbox', role: 'switch', checked: state.reachable.enabled, disabled: busy || state.reachable.editable === false,
          onChange: event => act('/reachable', { enabled: event.target.checked }) }),
      ] }),
      jsx('p', { className: 'cozychat-secondary', children: state.reachable.note || (state.reachable.enabled
        ? 'Hermes starts when you log in, so your phone can connect while this computer is awake.'
        : "Hermes keeps running until you quit it; it won't start by itself next time.") }),
    ] }))
  }
  return jsxs('div', { className: 'cozychat-page', children: [
    jsx('style', { children: CSS }), jsx('main', { className: 'cozychat-content', 'aria-busy': busy, children: contents }),
  ] })
}

function PairingPage({ ctx }) {
  const [model, setModel] = useState({ state: null, qr: null, busy: false, error: null, disabled: false })
  const [controller, setController] = useState(null)
  useEffect(() => {
    const instance = createController(ctx, setModel)
    setController(instance)
    instance.load(true)
    const poll = setInterval(() => instance.load(), 1000)
    const countdown = setInterval(() => instance.tick(), 1000)
    return () => { instance.dispose(); clearInterval(poll); clearInterval(countdown) }
  }, [ctx])
  return jsx(PairingView, { model, act: (...args) => controller?.act(...args) })
}

export default {
  id: 'cozychat',
  name: 'CozyChat',
  description: 'Pair your phone with Hermes on your home Wi-Fi.',
  register(ctx) {
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: '/cozychat' }, render: () => jsx(PairingPage, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: '/cozychat', label: 'CozyChat', codicon: 'device-mobile' } },
    ])
  },
}
