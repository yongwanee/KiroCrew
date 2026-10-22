import { useCallback, useRef, type RefObject } from 'react'

import { hasGesture, OPEN_MESSAGE_TYPE, openExternal, useFrameOpenLink } from './useFrameOpenLink'

/**
 * The web URL an open message asks for, or null when it is not one the link
 * bridge honours.
 *
 * Only an absolute `http:` or `https:` URL passes. `javascript:`, `data:`,
 * `blob:`, `file:`, `mailto:` and every custom scheme are refused, and so is a
 * URL carrying a user name or password, whose `user@host` form hides the real
 * host. The returned value is the PARSED form, so the URL that opens is exactly
 * the one the link's hover title shows.
 */
export function webUrlOf(data: unknown): string | null {
  if (!data || typeof data !== 'object') return null
  const msg = data as { type?: unknown; url?: unknown }
  if (msg.type !== OPEN_MESSAGE_TYPE || typeof msg.url !== 'string') return null
  if (!msg.url) return null
  let parsed: URL
  try {
    parsed = new URL(msg.url)
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  if (parsed.username || parsed.password) return null
  return parsed.href
}

/**
 * The host half of the link bridge for frames that hold agent-written pages
 * (saved artifacts, a teammate's shared artifact, chat widgets).
 *
 * Those frames are `sandbox="allow-scripts"` with no popup grant, so a page cannot
 * open a window itself. `buildSrcdoc({ linkBridge: true })` turns a `_blank` or
 * bare web link click, and a `window.open` call, into the same
 * `kirocrew-dashboard:open` message the crew pages use, and gives each web link a
 * hover title with its URL. This hook answers the message, the way a link in a
 * session opens:
 *
 * - only from one of the given frames (`event.source`);
 * - only for a web URL (`webUrlOf`);
 * - only while the person has just clicked or pressed a key in that frame
 *   (`hasGesture`), so a page posting on its own opens nothing;
 * - once per click: after opening, focus leaves the frame, so a page that posts
 *   again from the same click fails the gesture test until the next real click.
 */
export function useFrameLinkBridge(
  frames: ReadonlyArray<RefObject<HTMLIFrameElement | null>>,
  open: (url: string) => void = openExternal,
  gesture: (frame: HTMLIFrameElement) => boolean = hasGesture,
): void {
  const openRef = useRef(open)
  openRef.current = open
  // The frame, URL and gesture checks are useFrameOpenLink's own listener; this
  // hook adds the web-URL rule and the once-per-click blur.
  const openOnce = useCallback((url: string, frame?: HTMLIFrameElement) => {
    openRef.current(url)
    frame?.blur()
  }, [])
  useFrameOpenLink(frames, openOnce, gesture, webUrlOf)
}
