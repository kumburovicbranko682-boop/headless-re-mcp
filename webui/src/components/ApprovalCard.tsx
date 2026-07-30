import type { Approval } from "../agent/state";

type Props = { approval: Approval; onDecision: (approved: boolean) => void; busy?: boolean };
export function ApprovalCard({ approval, onDecision, busy = false }: Props) {
  return <article className="approval-card" aria-label={`Approval for ${approval.name}`}>
    <div className="risk-badge">{approval.effects.join(" + ")}</div>
    <h3>{approval.name}</h3>
    <pre>{JSON.stringify(approval.arguments, null, 2)}</pre>
    <p className="hash">args {approval.args_sha256.slice(0, 12)}…</p>
    <div className="approval-actions">
      <button disabled={busy} className="approve" onClick={() => onDecision(true)}>Approve once</button>
      <button disabled={busy} className="reject" onClick={() => onDecision(false)}>Reject</button>
    </div>
  </article>;
}
