import { recallSample, rememberSample } from "./sampleMemory";

describe("sampleMemory", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("recalls a sample by thread or session id", () => {
    rememberSample({ threadId: "t1", sessionId: "s1", path: "F:\\\\test.exe" });
    expect(recallSample("t1")?.name).toBe("test.exe");
    expect(recallSample(null, "s1")?.path).toBe("F:\\\\test.exe");
  });

  it("returns null when nothing was stored", () => {
    expect(recallSample("missing")).toBeNull();
  });
});
