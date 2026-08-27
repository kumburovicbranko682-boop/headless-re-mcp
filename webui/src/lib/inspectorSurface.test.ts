import {
  WORKSPACE_PROFILE_KEY,
  createTargetForProfile,
  inspectorSurface,
  isSessionLive,
  isWorkspaceProfile,
  openFormMode,
  peLiveMonitors,
  readStoredWorkspaceProfile,
} from "./inspectorSurface";

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

  it("accepts only the known workspace profiles", () => {
    expect(isWorkspaceProfile("pe")).toBe(true);
    expect(isWorkspaceProfile("web")).toBe(true);
    expect(isWorkspaceProfile("android")).toBe(true);
    expect(isWorkspaceProfile("full")).toBe(true);
    expect(isWorkspaceProfile("mobile")).toBe(false);
    expect(isWorkspaceProfile("")).toBe(false);
    expect(isWorkspaceProfile(null)).toBe(false);
    // A property that lives on Object.prototype must not pass as a profile.
    expect(isWorkspaceProfile("toString")).toBe(false);
    expect(isWorkspaceProfile("constructor")).toBe(false);
  });
});

describe("readStoredWorkspaceProfile", () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("returns a valid stored profile", () => {
    window.localStorage.setItem(WORKSPACE_PROFILE_KEY, "android");
    expect(readStoredWorkspaceProfile()).toBe("android");
  });

  it("falls back to null for a missing value so the landing shows", () => {
    expect(readStoredWorkspaceProfile()).toBeNull();
  });

  it("falls back to null for a stale/foreign value rather than trusting it", () => {
    // A profile name a past/future build wrote that this build no longer knows.
    window.localStorage.setItem(WORKSPACE_PROFILE_KEY, "mobile");
    expect(readStoredWorkspaceProfile()).toBeNull();
  });

  it("returns null instead of throwing when localStorage access throws", () => {
    // Safari private mode / disabled storage / sandboxed iframe. This runs in a
    // useState initializer during render, so a throw would crash the mount.
    vi.spyOn(window.localStorage, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    expect(() => readStoredWorkspaceProfile()).not.toThrow();
    expect(readStoredWorkspaceProfile()).toBeNull();
  });
});
