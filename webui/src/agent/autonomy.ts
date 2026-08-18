export type ApprovalMode = "request" | "full_access";

export type AutonomyPolicyView = {
  mode?: string;
  unattended?: boolean;
  auto_approve_effects?: string[];
  auto_approve_tools?: string[];
  never_auto_approve?: string[];
};

export type AutonomyResponse = {
  ok?: boolean;
  mode?: string;
  policy?: AutonomyPolicyView;
};

export function readApprovalMode(payload: AutonomyResponse | null | undefined): ApprovalMode {
  const raw = payload?.mode ?? payload?.policy?.mode;
  if (raw === "full_access") return "full_access";
  const effects = new Set(payload?.policy?.auto_approve_effects ?? []);
  if (effects.has("state_change") && effects.has("file_write")) return "full_access";
  return "request";
}
