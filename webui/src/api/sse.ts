export type SseEvent = { type: string; data: string; id?: string };

// The event stream is a text protocol, and the framing is not ours to assume.
// An event ends at a blank line, which the SSE spec lets a producer or any
// intermediary write as "\r\n\r\n", "\n\n" or "\r\r"; within a frame each field
// line ends the same three ways. Splitting only on "\n\n" folds a CRLF-framed
// stream into one never-terminated frame, so no event is ever dispatched.
const _FRAME_BOUNDARY = /\r\n\r\n|\n\n|\r\r/;
const _LINE_BOUNDARY = /\r\n|\r|\n/;

// Consume every complete frame from an accumulating buffer, returning the frames
// and the unterminated remainder to carry into the next read. A frame boundary
// can straddle two network reads, so the caller keeps ``rest`` and feeds it back.
export function splitSseFrames(buffer: string): { frames: string[]; rest: string } {
  const frames: string[] = [];
  let rest = buffer;
  let match = _FRAME_BOUNDARY.exec(rest);
  while (match) {
    frames.push(rest.slice(0, match.index));
    rest = rest.slice(match.index + match[0].length);
    match = _FRAME_BOUNDARY.exec(rest);
  }
  return { frames, rest };
}

// Parse one already-delimited frame into an event, or null when it carries no
// data line (a comment or a bare id/retry frame, which must not surface as an
// empty message). Multiple ``data:`` lines join with a newline -- concatenating
// them bare, as the old inline parser did, silently merged the lines of a
// multi-line payload into one unparseable string. A single leading space after
// the field colon is part of the framing, not the value, so it is dropped.
export function parseSseFrame(frame: string): SseEvent | null {
  let type = "message";
  let id: string | undefined;
  const dataLines: string[] = [];
  for (const line of frame.split(_LINE_BOUNDARY)) {
    if (line === "" || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") type = value;
    else if (field === "data") dataLines.push(value);
    else if (field === "id") id = value;
  }
  if (dataLines.length === 0) return null;
  const data = dataLines.join("\n");
  if (!data) return null;
  return { type, data, id };
}
