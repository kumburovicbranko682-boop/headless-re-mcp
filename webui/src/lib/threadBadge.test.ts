import { threadBadge, boundSessionId } from "./threadBadge";
import type { Thread } from "../agent/state";

const thread = (session_id: string | null): Thread => ({
  id: "t1",
  title: "分析对话",
  session_id,
  created_at: "",
  updated_at: "",
});

describe("threadBadge", () => {
  it("names a live session and marks restored ones dormant", () => {
    expect(threadBadge(thread(null), [], null)).toBe("对话");
    expect(threadBadge(thread("s1"), [{ id: "s1", binary: "C:\\keep.exe" }], null)).toBe("keep.exe");
    expect(threadBadge(thread("s1"), [{ id: "s1", binary: "C:\\keep.exe", metadata: { restored: true } }], null)).toContain("休眠");
  });

  it("only binds ids that are still listed", () => {
    expect(boundSessionId("s1", [{ id: "s1" }])).toBe("s1");
    expect(boundSessionId("s1", [])).toBe("");
  });
});
