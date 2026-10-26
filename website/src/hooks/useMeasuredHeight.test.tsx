import { describe, it, expect } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useMeasuredHeight } from './useMeasuredHeight'

/** A node whose ancestor is mid-scale: its bounding rect reads 95% of its layout height. */
function scaledNode(): HTMLDivElement {
  const node = document.createElement('div')
  Object.defineProperty(node, 'offsetHeight', { configurable: true, value: 200 })
  node.getBoundingClientRect = () => ({ height: 190, width: 0, top: 0, left: 0, right: 0, bottom: 190, x: 0, y: 0, toJSON: () => ({}) })
  return node
}

describe('useMeasuredHeight', () => {
  it('reads the bounding rect by default, transforms included', () => {
    const { result } = renderHook(() => useMeasuredHeight<HTMLDivElement>())
    act(() => result.current[0](scaledNode()))
    expect(result.current[1]).toBe(190)
  })

  it('reads the layout height with ignoreTransforms, so a scaling ancestor cannot undersize it', () => {
    const { result } = renderHook(() => useMeasuredHeight<HTMLDivElement>({ ignoreTransforms: true }))
    act(() => result.current[0](scaledNode()))
    expect(result.current[1]).toBe(200)
  })

  it('reports 0 once the node leaves', () => {
    const { result } = renderHook(() => useMeasuredHeight<HTMLDivElement>({ ignoreTransforms: true }))
    act(() => result.current[0](scaledNode()))
    act(() => result.current[0](null))
    expect(result.current[1]).toBe(0)
  })
})
