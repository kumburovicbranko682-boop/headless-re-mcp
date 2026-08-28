import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { downloadBlob } from "./downloadBlob";

// jsdom does not implement object URLs, so install observable stand-ins.
const created = "blob:vitest/download-blob";
let createSpy: ReturnType<typeof vi.fn>;
let revokeSpy: ReturnType<typeof vi.fn>;

describe("downloadBlob", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    createSpy = vi.fn(() => created);
    revokeSpy = vi.fn();
    vi.stubGlobal("URL", Object.assign(Object.create(URL), {
      createObjectURL: createSpy,
      revokeObjectURL: revokeSpy,
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("clicks an in-document link while the object URL is still live", () => {
    // Firefox ignores click() on a detached link, and every browser reads the
    // blob URL asynchronously after click() -- so the link must be in the DOM
    // and the URL must not have been revoked yet at click time.
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(function (this: HTMLAnchorElement) {
        expect(document.body.contains(this)).toBe(true);
        expect(this.getAttribute("href")).toBe(created);
        expect(this.download).toBe("dump.bin");
        expect(revokeSpy).not.toHaveBeenCalled();
      });

    downloadBlob(new Blob(["payload"]), "dump.bin");

    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("defers the revoke past the click tick instead of racing the download", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    downloadBlob(new Blob(["payload"]), "report.json");

    // Revoking synchronously is what aborted downloads: the browser had not
    // read the URL yet when it was invalidated.
    expect(revokeSpy).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revokeSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith(created);
  });
});
