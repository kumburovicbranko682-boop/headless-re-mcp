import { asFileName, readSession, sessionName, sessionStateLabel, targetLabel } from "./sessionLabel";

describe("session labels", () => {
  it("takes a filename from a Windows path", () => {
    expect(asFileName("E:\\samples\\app.exe")).toBe("app.exe");
  });

  it("does not crash when binary is not a string", () => {
    expect(sessionName({ id: "abc", binary: { path: "nope" } })).toBe("abc");
  });

  it("drops malformed session objects", () => {
    expect(readSession(null)).toBeNull();
    expect(readSession({ binary: "a.exe" })).toBeNull();
    expect(readSession({ id: "s1", binary: "C:\\a.exe", state: "created" })).toEqual({
      id: "s1",
      binary: "C:\\a.exe",
      locator: undefined,
      state: "created",
      target: undefined,
      metadata: undefined,
    });
  });

  it("labels a restored session as dormant", () => {
    const session = readSession({
      id: "s2",
      binary: "C:\\keep.exe",
      state: "created",
      metadata: { restored: true },
    });
    expect(session?.metadata).toEqual({ restored: true });
    expect(sessionStateLabel(session!)).toContain("休眠");
  });

  it("maps session targets", () => {
    expect(targetLabel("web")).toBe("Web");
    expect(targetLabel("apk")).toBe("APK");
    expect(targetLabel("pe")).toBe("PE");
  });
});
