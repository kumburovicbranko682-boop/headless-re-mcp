import { inspectorDisconnectedHint, isSessionGone, reconnectHint, staleSessionHint, dormantHint } from "./sessionGone";

describe("sessionGone", () => {
  it("detects missing analysis sessions", () => {
    expect(isSessionGone({ code: "session_not_found" })).toBe(true);
    expect(isSessionGone({ message: "session not found: abc" })).toBe(true);
    expect(isSessionGone({ message: "timeout" })).toBe(false);
  });

  it("keeps the chat and names the file to reopen", () => {
    const text = reconnectHint("test.exe");
    expect(text).toContain("对话");
    expect(text).not.toContain("已失效");
    expect(text).toContain("test.exe");
    expect(staleSessionHint()).toContain("对话");
    expect(inspectorDisconnectedHint()).toContain("监视");
    expect(dormantHint()).toContain("同一 ID");
  });
});
