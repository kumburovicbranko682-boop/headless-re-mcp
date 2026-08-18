import type { Approval } from "../agent/state";

type Remember = "tool" | "effect";
type Props = {
  approval: Approval;
  onDecision: (approved: boolean, remember?: Remember) => void;
  busy?: boolean;
};

export function ApprovalCard({ approval, onDecision, busy = false }: Props) {
  return (
    <article className="approval-card" aria-label={`批准 ${approval.name}`}>
      <div className="risk-badge">{approval.effects.join(" + ")}</div>
      <h3>{approval.name}</h3>
      <pre>{JSON.stringify(approval.arguments, null, 2)}</pre>
      <p className="hash">参数 {approval.args_sha256.slice(0, 12)}…</p>
      <div className="approval-actions">
        <button disabled={busy} className="approve" onClick={() => onDecision(true)}>批准一次</button>
        <button disabled={busy} className="approve-always" onClick={() => onDecision(true, "tool")}>永远允许此工具</button>
        <button disabled={busy} className="approve-always" onClick={() => onDecision(true, "effect")}>永远允许同类</button>
        <button disabled={busy} className="reject" onClick={() => onDecision(false)}>拒绝</button>
      </div>
    </article>
  );
}
