import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { useRef } from 'react'
import { OPEN_MESSAGE_TYPE } from './useFrameOpenLink'
import { useFrameLinkBridge, webUrlOf } from './useFrameLinkBridge'

const URL_A = 'https://github.com/example-org/repo/pull/7'

/** A host with one frame. The frame's window is a unique object: the hook compares identity only. */
function Host({ frame, open, gesture }: {
  frame: HTMLIFrameElement
  open: (url: string) => void
  gesture?: (frame: HTMLIFrameElement) => boolean
}) {
  const ref = useRef<HTMLIFrameElement | null>(frame)
  useFrameLinkBridge([ref], open, gesture ?? (() => true))
  return null
}

function fakeFrame(): HTMLIFrameElement {
  return { contentWindow: {} as Window, blur: vi.fn() } as unknown as HTMLIFrameElement
}

function post(data: unknown, source: unknown) {
  const event = new MessageEvent('message', { data })
  Object.defineProperty(event, 'source', { value: source })
  act(() => { window.dispatchEvent(event) })
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useFrameLinkBridge', () => {
  it('opens on a real click in its frame, with no dialog', () => {
    const frame = fakeFrame()
    const open = vi.fn()
    render(<Host frame={frame} open={open} />)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, frame.contentWindow)
    expect(open).toHaveBeenCalledTimes(1)
    expect(open).toHaveBeenCalledWith(URL_A)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('opens nothing without a click in that frame', () => {
    const frame = fakeFrame()
    const open = vi.fn()
    render(<Host frame={frame} open={open} gesture={() => false} />)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, frame.contentWindow)
    expect(open).not.toHaveBeenCalled()
  })

  it('opens once per click: focus leaves the frame, so a page posting again opens nothing', () => {
    const frame = document.createElement('iframe')
    frame.tabIndex = 0
    document.body.appendChild(frame)
    const frameWindow = {} as Window
    Object.defineProperty(frame, 'contentWindow', { configurable: true, value: frameWindow })
    const open = vi.fn()
    try {
      render(<Host frame={frame} open={open} gesture={(f) => document.activeElement === f} />)
      frame.focus()
      expect(document.activeElement).toBe(frame)
      post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, frameWindow)
      post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, frameWindow)
      post({ type: OPEN_MESSAGE_TYPE, url: 'https://example.test/other' }, frameWindow)
      expect(open).toHaveBeenCalledTimes(1)
      expect(document.activeElement).not.toBe(frame)
    } finally {
      frame.remove()
    }
  })

  it('ignores a message from a window that is not its frame', () => {
    const frame = fakeFrame()
    const open = vi.fn()
    render(<Host frame={frame} open={open} />)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, {} as Window)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, window)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, null)
    expect(open).not.toHaveBeenCalled()
  })

  it.each([
    'javascript:alert(1)',
    'data:text/html,<p>x</p>',
    'blob:https://example.test/0b1c',
    'file:///etc/hosts',
    'mailto:someone@example.test',
    'vscode://file/x',
    '/relative/path',
    'https://user:pass@example.test/',
    'https://github.com@evil.example/',
  ])('refuses %s', (url) => {
    const frame = fakeFrame()
    const open = vi.fn()
    render(<Host frame={frame} open={open} />)
    post({ type: OPEN_MESSAGE_TYPE, url }, frame.contentWindow)
    expect(open).not.toHaveBeenCalled()
  })

  it('opens the parsed URL, so what the hover title shows is what opens', () => {
    expect(webUrlOf({ type: OPEN_MESSAGE_TYPE, url: 'HTTPS://Example.TEST/a b' })).toBe('https://example.test/a%20b')
    expect(webUrlOf({ type: OPEN_MESSAGE_TYPE, url: 'http://example.test' })).toBe('http://example.test/')
    expect(webUrlOf({ type: 'kirocrew-dashboard:act', url: URL_A })).toBeNull()
    const long = `https://example.test/${'a'.repeat(4096)}`
    expect(webUrlOf({ type: OPEN_MESSAGE_TYPE, url: long })).toBe(long)
  })

  it('opens through window.open with noopener and noreferrer by default', () => {
    const frame = fakeFrame()
    const spy = vi.spyOn(window, 'open').mockImplementation(() => null)
    function DefaultHost() {
      const ref = useRef<HTMLIFrameElement | null>(frame)
      useFrameLinkBridge([ref], undefined, () => true)
      return null
    }
    render(<DefaultHost />)
    post({ type: OPEN_MESSAGE_TYPE, url: URL_A }, frame.contentWindow)
    expect(spy).toHaveBeenCalledWith(URL_A, '_blank', 'noopener,noreferrer')
  })
})
