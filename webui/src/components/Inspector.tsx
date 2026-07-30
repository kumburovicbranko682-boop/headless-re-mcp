import type { RunEvent } from "../agent/state";

type Props = { events: RunEvent[]; monitor: unknown; artifacts: unknown; audit: unknown };
export function Inspector({ events, monitor, artifacts, audit }: Props) {
  return <aside className="inspector">
    <header><strong>Inspector</strong><span className="live-dot">live</span></header>
    <details open><summary>Tool events</summary><div className="event-list">{events.slice(-30).reverse().map((event) => <div className="event" key={`${event.run_id}-${event.seq}`}><b>{event.seq}</b><span>{event.type}</span></div>)}</div></details>
    <details><summary>Monitor</summary><pre>{JSON.stringify(monitor, null, 2)}</pre></details>
    <details><summary>Timeline / Artifacts</summary><pre>{JSON.stringify(artifacts, null, 2)}</pre></details>
    <details><summary>Audit</summary><pre>{JSON.stringify(audit, null, 2)}</pre></details>
  </aside>;
}
