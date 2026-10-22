/** Executes the popped-out widget tab's link bridge (`popoutLinkBridgeScript`)
 * against stand-ins for that tab's window, document and navigator, and pins the
 * same rules the in-dashboard bridge keeps: only its own frame, only a web URL,
 * only right after a click in the frame, once per click, and no dialog.
 */
import { describe, it, expect, vi } from 'vitest'
import { popoutLinkBridgeScript } from '../lib/widgetSrcdoc'

const OPEN = 'kirocrew-dashboard:open'
const LINK = 'https://code.example.test/reviews/CR-1'

function setup({ active = true, focused = true } = {}) {
  const frameWindow = {}
  let isFocused = focused
  const frame = { contentWindow: frameWindow, blur: () => { isFocused = false } }
  let onMessage: ((e: { source: unknown; data: unknown }) => void) | null = null
  const confirm = vi.fn(() => true)
  const open = vi.fn()
  const win = {
    addEventListener: (type: string, fn: (e: { source: unknown; data: unknown }) => void) => {
      if (type === 'message') onMessage = fn
    },
    confirm,
    open,
  }
  const doc = {
    querySelector: (sel: string) => (sel === 'iframe' ? frame : null),
    get activeElement() { return isFocused ? frame : {} },
  }
  const nav = { userActivation: { isActive: active } }
  new Function('window', 'document', 'navigator', popoutLinkBridgeScript())(win, doc, nav)
  const send = (data: unknown, source: unknown = frameWindow) => onMessage?.({ source, data })
  return { send, confirm, open }
}

describe('popped-out widget link bridge', () => {
  it('opens on a real click without an opener, and asks nothing', () => {
    const { send, confirm, open } = setup()
    send({ type: OPEN, url: LINK })
    expect(open).toHaveBeenCalledWith(LINK, '_blank', 'noopener,noreferrer')
    expect(confirm).not.toHaveBeenCalled()
  })

  it('opens once per click, however many requests the page queues', () => {
    const { send, open } = setup()
    send({ type: OPEN, url: LINK })
    send({ type: OPEN, url: LINK })
    send({ type: OPEN, url: 'https://example.test/other' })
    expect(open).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['no activation', { active: false }],
    ['focus elsewhere', { focused: false }],
  ])('opens nothing with %s', (_label, opts) => {
    const { send, open } = setup(opts)
    send({ type: OPEN, url: LINK })
    expect(open).not.toHaveBeenCalled()
  })

  it.each([
    'javascript:alert(1)',
    'data:text/html,x',
    'file:///etc/hosts',
    'mailto:a@example.test',
    '/relative',
    'https://user:pass@example.test/',
  ])('refuses %s', (url) => {
    const { send, open } = setup()
    send({ type: OPEN, url })
    expect(open).not.toHaveBeenCalled()
  })

  it('ignores another window and another message type', () => {
    const { send, open } = setup()
    send({ type: OPEN, url: LINK }, {})
    send({ type: 'kirocrew-dashboard:act', url: LINK })
    expect(open).not.toHaveBeenCalled()
  })
})
