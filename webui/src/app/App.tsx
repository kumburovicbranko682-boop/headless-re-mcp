import type { KeyboardEvent } from "react";
import { ApprovalCard } from "../components/ApprovalCard";
import { ApprovalModeControl } from "../components/ApprovalModeControl";
import { ChatMessage, ThinkingMessage } from "../components/ChatMessage";
import { Inspector } from "../components/Inspector";
import { McpExportModal } from "../components/McpExportModal";
import { OpenTarget } from "../components/OpenTarget";
import { RunProgress } from "../components/RunProgress";
import { SessionRail } from "../components/SessionRail";
import { SettingsModal } from "../components/SettingsModal";
import { ThemeToggle } from "../components/ThemeToggle";
import { ThreadList } from "../components/ThreadList";
import { WorkspaceLanding } from "../components/WorkspaceLanding";
import { SessionReconnect } from "../components/SessionReconnect";
import { PROFILE_LABEL } from "../lib/inspectorSurface";
import { sessionName, sessionStateLabel } from "../lib/sessionLabel";
import { dormantHint } from "../lib/sessionGone";
import { useTheme } from "../lib/theme";
import { useWorkbench } from "./useWorkbench";

export function App() {
  const wb = useWorkbench();
  const { theme, toggle } = useTheme();

  if (wb.landingOpen) {
    return <WorkspaceLanding onChoose={wb.chooseProfile} />;
  }

  const selectedThread = (Array.isArray(wb.state.threads) ? wb.state.threads : []).find((thread) => thread.id === wb.state.selectedThread);
  const onComposerKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void wb.send();
    }
  };

  return (
    <div className="agent">
      <aside className="navpane">
        <div className="navpane-brand">
          <span className="brand-mark" aria-hidden="true">
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2.5 3.5 7 8l-4.5 4.5" />
              <path d="M8.5 12.5h5" />
            </svg>
          </span>
          <div className="navpane-brand-copy">
            <strong>Headless RE-MCP</strong>
            <small>{wb.workspaceProfile ? PROFILE_LABEL[wb.workspaceProfile] : "未选方向"}</small>
          </div>
        </div>
        <ThreadList
          threads={Array.isArray(wb.state.threads) ? wb.state.threads : []}
          selectedId={wb.state.selectedThread}
          sessions={wb.sessions}
          lost={wb.lost}
          onSelect={(id) => void wb.selectThread(id)}
          onRemove={(id) => void wb.removeThread(id)}
          onCreate={() => void wb.createThread()}
        />
        <SessionRail
          sessions={wb.sessions}
          selectedId={wb.liveSessionId}
          unlinkLabel={wb.unlinkLabel}
          onSelect={(id) => void wb.changeSession(id)}
          onRefresh={() => void wb.loadSessions()}
        />
        <OpenTarget
          formMode={wb.formMode}
          pathLabel={wb.pathLabel}
          pathPlaceholder={wb.pathPlaceholder}
          binaryPath={wb.binaryPath}
          onPathChange={wb.setBinaryPath}
          picking={wb.picking}
          opening={wb.opening}
          pendingName={wb.pendingName}
          liveSessionId={wb.liveSessionId}
          openHint={wb.openHint}
          onPick={() => void wb.pickBinary()}
          onOpen={() => void wb.openPickedSession(wb.binaryPath)}
        />
      </aside>

      <section className="conversation">
        <header className="chat-head">
          <div className="chat-head-copy">
            <h1>{selectedThread?.title || "新对话"}</h1>
            <p>
              {wb.personaTitle || "分析助手"}
              {" · "}
              {wb.state.connected ? "已连接" : "本机"}
              {wb.approvalMode === "full_access" ? " · 完全访问" : " · 写操作需批准"}
            </p>
          </div>
          {wb.liveSession && (
            <span className={`specimen-tag${wb.liveSession.metadata?.restored ? " dormant" : ""}`}>
              {sessionName(wb.liveSession)}
              <small>{wb.liveSession.metadata?.restored ? "休眠" : sessionStateLabel(wb.liveSession)}</small>
            </span>
          )}
          <div className="chat-head-actions">
            <button type="button" className="ghost-btn" onClick={() => wb.setLandingOpen(true)}>方向</button>
            {wb.state.activeRun && (
              <button className="cancel" type="button" onClick={() => void wb.cancelRun()}>停止</button>
            )}
            <button type="button" className="ghost-btn" onClick={() => wb.setSettingsOpen(true)}>设置</button>
            <button type="button" className="ghost-btn" onClick={() => wb.setMcpOpen(true)}>MCP</button>
            <ThemeToggle theme={theme} onToggle={toggle} />
          </div>
        </header>

        <div className="transcript">
          {wb.visibleMessages.length === 0 && !wb.state.streamingText && !wb.state.activeRun && (
            <div className="empty">
              <h2>有什么想分析的？</h2>
              <p>在左侧打开或选择会话，然后直接提问。控制台重启后，同一会话还会在。</p>
            </div>
          )}
          {wb.state.messages.length > 80 && (
            <div className="empty"><p>只显示最近 80 条，更早的内容仍保留在对话里。</p></div>
          )}
          {wb.visibleMessages.map((message) => (
            <ChatMessage key={message.id} role={message.role} content={message.content} />
          ))}
          {wb.state.activeRun && <ThinkingMessage text={wb.state.streamingReasoning} />}
          {wb.state.streamingText && (
            <ChatMessage role="assistant" content={wb.state.streamingText} streaming={Boolean(wb.state.activeRun)} />
          )}
          {wb.state.approvals.map((approval) => (
            <ApprovalCard
              key={approval.tool_call_id}
              approval={approval}
              onDecision={(approved, remember) => void wb.decide(approval.tool_call_id, approval.args_sha256, approved, remember)}
            />
          ))}
          {wb.liveSession?.metadata?.restored && !wb.lost && <div className="dormant-banner">{dormantHint()}</div>}
          {wb.lost && !wb.liveSessionId && <SessionReconnect lost={wb.lost} busy={wb.opening} onReopen={wb.reopenLost} />}
          {wb.state.error && !(wb.lost && !wb.liveSessionId) && <div className="error">{wb.state.error}</div>}
          <div ref={wb.bottomRef} />
        </div>

        <div className="composer-dock">
          {(wb.state.activeRun || wb.state.events.length > 0) && (
            <RunProgress events={wb.state.events} rounds={Math.max(1, wb.state.messages.filter((message) => message.role === "user").length)} />
          )}
          <div className="composer-row">
            <form className="composer" onSubmit={(event) => { event.preventDefault(); void wb.send(); }}>
              <textarea
                aria-label="消息"
                value={wb.draft}
                onChange={(event) => wb.setDraft(event.target.value)}
                onKeyDown={onComposerKey}
                placeholder="询问这个样本，或让助手执行下一步。Enter 发送，Shift+Enter 换行"
                rows={3}
              />
              {wb.state.activeRun
                ? <button type="button" className="composer-stop" onClick={() => void wb.cancelRun()}>停止</button>
                : <button disabled={!wb.draft.trim()}>发送</button>}
            </form>
            <ApprovalModeControl mode={wb.approvalMode} busy={wb.approvalBusy} onChange={(mode) => void wb.changeApprovalMode(mode)} />
          </div>
        </div>
      </section>

      <Inspector
        events={wb.state.events}
        sessionId={wb.liveSessionId}
        profile={wb.workspaceProfile}
        sessionTarget={wb.liveSession?.target}
        sessionState={wb.liveSession?.state}
        locator={wb.liveSession?.locator || wb.liveSession?.binary}
        sessionRestored={Boolean(wb.liveSession?.metadata?.restored)}
        disconnected={wb.lost && !wb.liveSessionId ? wb.lost : null}
        onSessionMissing={wb.noteMissingSession}
        onSessionClosed={wb.noteClosedSession}
        onReopen={wb.reopenLost}
      />

      {wb.settingsOpen && (
        <SettingsModal
          approvalMode={wb.approvalMode}
          approvalBusy={wb.approvalBusy}
          onApprovalModeChange={(mode) => void wb.changeApprovalMode(mode)}
          onClose={() => wb.setSettingsOpen(false)}
        />
      )}
      {wb.mcpOpen && <McpExportModal onClose={() => wb.setMcpOpen(false)} />}
    </div>
  );
}
