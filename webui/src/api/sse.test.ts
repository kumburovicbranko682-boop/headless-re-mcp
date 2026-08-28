import { parseSseFrame, splitSseFrames } from "./sse";

describe("splitSseFrames", () => {
  it("splits LF-framed events and keeps the unterminated remainder", () => {
    const { frames, rest } = splitSseFrames("event: a\ndata: 1\n\nevent: b\ndata: 2");
    expect(frames).toEqual(["event: a\ndata: 1"]);
    expect(rest).toBe("event: b\ndata: 2");
  });

  it("splits CRLF-framed events, which the old \\n\\n scan never separated", () => {
    const { frames, rest } = splitSseFrames("event: a\r\ndata: 1\r\n\r\nevent: b\r\ndata: 2\r\n\r\n");
    expect(frames).toEqual(["event: a\r\ndata: 1", "event: b\r\ndata: 2"]);
    expect(rest).toBe("");
  });

  it("carries a frame boundary that straddles two reads", () => {
    // The boundary "\n\n" arrives split across reads: "...1\n" then "\ndata: 2".
    const first = splitSseFrames("data: 1\n");
    expect(first.frames).toEqual([]);
    expect(first.rest).toBe("data: 1\n");
    const second = splitSseFrames(first.rest + "\ndata: 2");
    expect(second.frames).toEqual(["data: 1"]);
    expect(second.rest).toBe("data: 2");
  });
});

describe("parseSseFrame", () => {
  it("parses a single-line event with id, event and data", () => {
    expect(parseSseFrame("id: 7\nevent: tool.result\ndata: {\"ok\":true}")).toEqual({
      type: "tool.result",
      data: "{\"ok\":true}",
      id: "7",
    });
  });

  it("defaults the type to message when no event field is present", () => {
    expect(parseSseFrame("data: hello")).toEqual({ type: "message", data: "hello" });
  });

  it("joins multiple data lines with a newline instead of concatenating them", () => {
    // The old parser produced "line1line2", an unparseable merge of the payload.
    expect(parseSseFrame("data: line1\ndata: line2")).toEqual({
      type: "message",
      data: "line1\nline2",
    });
  });

  it("keeps a CRLF frame's fields intact", () => {
    expect(parseSseFrame("event: heartbeat\r\ndata: {\"after\":3}")).toEqual({
      type: "heartbeat",
      data: "{\"after\":3}",
    });
  });

  it("strips only a single leading space after the field colon", () => {
    expect(parseSseFrame("data:  two-spaces")).toEqual({ type: "message", data: " two-spaces" });
  });

  it("ignores comment lines and frames that carry no data", () => {
    expect(parseSseFrame(": keep-alive")).toBeNull();
    expect(parseSseFrame("event: heartbeat\nid: 9")).toBeNull();
  });
});
