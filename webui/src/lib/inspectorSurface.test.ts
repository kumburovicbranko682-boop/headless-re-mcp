import { createTargetForProfile, inspectorSurface, isSessionLive, openFormMode, peLiveMonitors } from "./inspectorSurface";

describe("inspector surface", () => {
  it("uses the bound session target even when the workspace profile differs", () => {
    expect(inspectorSurface({ profile: "web", target: "pe", hasSession: true })).toBe("pe");
    expect(inspectorSurface({ profile: "pe", target: "web", hasSession: true })).toBe("web");
    expect(inspectorSurface({ profile: "web", hasSession: false })).toBe("web");
  });

  it("opens a URL session from the web profile and a file session from PE", () => {
    expect(createTargetForProfile("web", "https://example.com/app")).toBe("web");
    expect(createTargetForProfile("pe", "F:\\test.exe")).toBe("pe");
    expect(createTargetForProfile("full", "https://example.com")).toBe("web");
    expect(createTargetForProfile("android", "C:\\app.apk")).toBe("apk");
  });

  it("hides the PE live monitors on a closed PE session", () => {
    expect(peLiveMonitors("pe", true, "created")).toBe(true);
    expect(peLiveMonitors("pe", true, "closed")).toBe(false);
    expect(peLiveMonitors("web", true, "created")).toBe(false);
    expect(isSessionLive("closed")).toBe(false);
  });

  it("switches the sidebar opener with the workspace profile", () => {
    expect(openFormMode("web")).toBe("url");
    expect(openFormMode("android")).toBe("apk");
    expect(openFormMode("pe")).toBe("file");
    expect(openFormMode("full")).toBe("file");
  });
});
