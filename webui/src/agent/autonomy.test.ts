import { readApprovalMode } from "./autonomy";

describe("readApprovalMode", () => {
  it("prefers the top-level mode field", () => {
    expect(readApprovalMode({ mode: "full_access", policy: { mode: "request" } })).toBe("full_access");
    expect(readApprovalMode({ mode: "request" })).toBe("request");
  });

  it("treats both write effect classes as full access when mode is missing", () => {
    expect(readApprovalMode({
      policy: { auto_approve_effects: ["state_change", "file_write"] },
    })).toBe("full_access");
  });

  it("keeps a partial grant as request", () => {
    expect(readApprovalMode({
      policy: { auto_approve_effects: ["state_change"], auto_approve_tools: ["dynamic.open"] },
    })).toBe("request");
    expect(readApprovalMode(null)).toBe("request");
  });
});
