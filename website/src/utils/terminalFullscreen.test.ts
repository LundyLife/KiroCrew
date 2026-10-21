import { describe, expect, it } from 'vitest'
import { isTerminalFullscreenAllowed, mainStackingClass } from './terminalFullscreen'

describe('isTerminalFullscreenAllowed', () => {
  it('allows fullscreen on desktop', () => {
    expect(isTerminalFullscreenAllowed(false)).toBe(true)
  })
  it('forbids fullscreen on a mobile viewport', () => {
    expect(isTerminalFullscreenAllowed(true)).toBe(false)
  })
})

describe('mainStackingClass', () => {
  const docked = { terminalEnabled: true, terminalPoppedOut: false }

  it('isolates <main> only when a maximized dock panel is actually on screen', () => {
    expect(mainStackingClass({ isTerminalFullscreen: true, ...docked })).toBe('isolate')
  })
  it('adds no stacking class when the terminal is not fullscreen', () => {
    // Docked but not maximized: a page-level inline modal must paint over the dock.
    expect(mainStackingClass({ isTerminalFullscreen: false, ...docked })).toBe('')
  })
  it('adds no stacking class when the maximized terminal is popped out', () => {
    // The fullscreen flag persists across pop-out, but no panel is on screen, so
    // isolating <main> would trap a page modal inside it for nothing.
    expect(mainStackingClass({ isTerminalFullscreen: true, terminalEnabled: true, terminalPoppedOut: true })).toBe('')
  })
  it('adds no stacking class when the terminal is disabled while the flag is still set', () => {
    expect(mainStackingClass({ isTerminalFullscreen: true, terminalEnabled: false, terminalPoppedOut: false })).toBe('')
  })
})
