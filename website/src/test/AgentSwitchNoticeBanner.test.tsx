import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent, waitFor } from '@testing-library/react'
import { Routes, Route, useSearchParams } from 'react-router-dom'
import AgentSwitchNoticeBanner from '../components/AgentSwitchNoticeBanner'
import { setAgentSwitchNotice } from '../store/chatSlice'
import { renderWithProviders, createTestStore } from './helpers'
import { useAppSelector } from '../store'

const createChatSlot = vi.fn()
vi.mock('../api/client', async importOriginal => {
  const mod = await importOriginal<typeof import('../api/client')>()
  return { ...mod, api: { ...mod.api, createChatSlot: (...a: unknown[]) => createChatSlot(...a) } }
})

function ChatTarget() {
  const [params] = useSearchParams()
  return <div data-testid="chat-target">{params.get('sid')}</div>
}

function BannerFromStore() {
  const n = useAppSelector(s => s.chat.agentSwitchNotice)
  return n ? <AgentSwitchNoticeBanner notice={n} /> : null
}

function renderBanner(notice: { message: string; newChatAgent?: string }) {
  const store = createTestStore()
  store.dispatch(setAgentSwitchNotice(notice))
  const ui = (
    <Routes>
      <Route path="/chat" element={<><ChatTarget /><BannerFromStore /></>} />
    </Routes>
  )
  return renderWithProviders(ui, { store, route: '/chat?sid=old-chat' })
}

describe('AgentSwitchNoticeBanner', () => {
  beforeEach(() => {
    createChatSlot.mockReset()
  })

  it('shows a plain notice with no new-chat button', () => {
    renderBanner({ message: 'invalid agent name' })
    expect(screen.getByTestId('agent-switch-notice').textContent).toContain('invalid agent name')
    expect(screen.queryByTestId('agent-switch-notice-new-chat')).toBeNull()
  })

  it('opens a new chat on the refused crewmate and clears the notice', async () => {
    createChatSlot.mockResolvedValue({ key: 'new-chat', agent: 'writer', agent_kind: 'member', messages: [] })
    const { store } = renderBanner({ message: 'writer has its own memory', newChatAgent: 'writer' })
    const button = screen.getByTestId('agent-switch-notice-new-chat')
    expect(button.textContent).toBe('New chat with writer')
    fireEvent.click(button)
    await waitFor(() => expect(screen.getByTestId('chat-target').textContent).toBe('new-chat'))
    // createChatSlot(project, agent, model, mode, memory_mode, title, color, folderId, agentKind, ...)
    expect(createChatSlot).toHaveBeenCalledTimes(1)
    const args = createChatSlot.mock.calls[0]
    expect(args[1]).toBe('writer')
    expect(args[8]).toBe('member')
    expect(store.getState().chat.agentSwitchNotice).toBeNull()
  })

  it('keeps the user on the chat and reports a failed create', async () => {
    createChatSlot.mockRejectedValue(new Error('create failed'))
    const { store } = renderBanner({ message: 'writer has its own memory', newChatAgent: 'writer' })
    fireEvent.click(screen.getByTestId('agent-switch-notice-new-chat'))
    await waitFor(() => expect(store.getState().chat.agentSwitchNotice?.message).toBe('create failed'))
    expect(store.getState().chat.agentSwitchNotice?.newChatAgent).toBeUndefined()
    expect(screen.getByTestId('chat-target').textContent).toBe('old-chat')
  })
})
