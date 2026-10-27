import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X } from 'lucide-react'
import { useAppDispatch } from '../store'
import { createSlot, setAgentSwitchNotice } from '../store/chatSlice'
import type { AgentSwitchNotice } from '../utils/agentSwitchFeedback'
import { errMessage } from '../utils/thunkError'
import { i18nT } from '../i18n/t'

/**
 * The shared agent-switch notice. When the refused pick was a crewmate that can
 * only start a new chat, the notice offers that new chat: a session created on
 * the crewmate, filed like the New button's, and opened. The chat the pick was
 * made in keeps its agent and history either way.
 */
export default function AgentSwitchNoticeBanner({ notice }: { notice: AgentSwitchNotice }) {
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  const agent = notice.newChatAgent
  const openNewChat = async () => {
    if (!agent || creating) return
    setCreating(true)
    try {
      const slot = await dispatch(createSlot({ agent, agent_kind: 'member', defaultFolder: true })).unwrap()
      dispatch(setAgentSwitchNotice(null))
      if (slot?.key) navigate(`/chat?sid=${encodeURIComponent(slot.key)}`)
    } catch (err) {
      // `unwrap()` rejects with a serialized plain object; errMessage reads it.
      dispatch(setAgentSwitchNotice(errMessage(err) || i18nT('components.errorBoundary.something_went_wrong')))
    } finally {
      setCreating(false)
    }
  }
  return (
    <div role="status" data-testid="agent-switch-notice" className="fixed z-[70] top-safe-offset-14 left-safe-offset-4 right-safe-offset-4 sm:left-auto sm:w-[440px] bg-bg-elevated border rounded-lg p-3 flex items-center gap-3 shadow-xl animate-rise" style={{ borderColor: 'color-mix(in srgb, var(--warn) 45%, transparent)' }}>
      <span className="text-sm text-text flex-1">{notice.message}</span>
      {agent && (
        <button
          type="button"
          onClick={openNewChat}
          disabled={creating}
          data-testid="agent-switch-notice-new-chat"
          className="shrink-0 text-[12px] font-medium px-2 py-1 rounded-md border border-border text-text hover:bg-bg-hover disabled:opacity-60 cursor-pointer"
        >
          {i18nT('utils.agentSwitchFeedback.new_chat_with', { name: agent })}
        </button>
      )}
      <button onClick={() => dispatch(setAgentSwitchNotice(null))} aria-label={i18nT('app.dismiss')} className="text-muted hover:text-text leading-none p-0.5"><X className="lucide-inline w-4 h-4" /></button>
    </div>
  )
}
