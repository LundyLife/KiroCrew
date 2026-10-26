import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { GHOST_GAMES, GhostGameLoader, labelStem, pickLoaderChoice } from '../components/GhostGames'

describe('labelStem', () => {
  it('drops a trailing ellipsis glyph or three ASCII dots', () => {
    expect(labelStem('Thinking…')).toBe('Thinking')
    expect(labelStem('Réflexion...')).toBe('Réflexion')
  })

  it('returns null when there is no trailing ellipsis to eat', () => {
    expect(labelStem('思考中')).toBeNull()
    expect(labelStem('Thinking… now')).toBeNull()
  })
})

describe('pickLoaderChoice', () => {
  /** Every value the draw can land on, sweeping the random source across [0, 1). */
  const reachable = (label: string) => {
    const seen = new Set<string>()
    for (let i = 0; i < 100; i++) seen.add(pickLoaderChoice(label, () => i / 100))
    return seen
  }

  it('can land on the carousel and on every game', () => {
    expect(reachable('Thinking…')).toEqual(new Set(['carousel', ...GHOST_GAMES]))
  })

  it('never draws the ellipsis game for a label without an ellipsis', () => {
    const seen = reachable('思考中')
    expect(seen.has('ellipsis')).toBe(false)
    expect(seen.size).toBe(GHOST_GAMES.length)
  })

  it('stays in range at the top of the random source', () => {
    expect(pickLoaderChoice('Thinking…', () => 0.9999999)).toBe(GHOST_GAMES[GHOST_GAMES.length - 1])
  })
})

describe('GhostGameLoader', () => {
  it.each(GHOST_GAMES)('%s is decorative brand art: aria-hidden <img> assets, no inline svg', game => {
    const { container, getByTestId } = render(<GhostGameLoader game={game} />)
    const root = getByTestId('loader-game')
    expect(root).toHaveAttribute('data-game', game)
    expect(root).toHaveAttribute('aria-hidden', 'true')
    expect(container.querySelector('svg')).toBeNull()
    const imgs = container.querySelectorAll('img')
    expect(imgs.length).toBeGreaterThan(0)
    imgs.forEach(img => {
      expect(img).toHaveAttribute('alt', '')
      expect(img.getAttribute('src')).toBeTruthy()
    })
  })
})
