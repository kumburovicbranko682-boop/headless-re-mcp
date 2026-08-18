export type DesktopSnapshotHint = {
  available?: boolean;
  window_count?: number;
  debuggee_state?: string | null;
  desktop_window_count?: number;
  hint?: string | null;
};

export function desktopPreviewTitle(snapshot: DesktopSnapshotHint | null): string {
  if (!snapshot?.available) return '\u6b63\u5728\u6253\u5f00\u865a\u62df\u684c\u9762';
  if ((snapshot.window_count ?? 0) > 0) return '\u6b63\u5728\u76d1\u89c6';
  if (snapshot.debuggee_state === 'paused') return '\u5df2\u542f\u52a8\uff0c\u505c\u5728\u5165\u53e3';
  return '\u6b63\u5728\u76d1\u89c6';
}

export function desktopPreviewHint(snapshot: DesktopSnapshotHint | null): string {
  if (!snapshot?.available) {
    return '\u4f1a\u8bdd\u521d\u59cb\u5316\u65f6\u4f1a\u81ea\u52a8\u6253\u5f00 x64dbg \u9690\u85cf\u684c\u9762\u3002';
  }
  if ((snapshot.window_count ?? 0) > 0) return '\u7b49\u5f85\u7b2c\u4e00\u5e27\u2026';
  if (snapshot.debuggee_state === 'paused') {
    return '\u76ee\u6807\u505c\u5728\u5165\u53e3\u65ad\u70b9\uff0c\u8fd8\u6ca1\u6267\u884c\u5230\u521b\u5efa\u7a97\u53e3\u3002\u70b9\u300c\u7ee7\u7eed\u8fd0\u884c\u300d\u540e\u754c\u9762\u624d\u4f1a\u51fa\u73b0\u3002';
  }
  if (snapshot.debuggee_state === 'running') {
    return '\u76ee\u6807\u5728\u8dd1\uff0c\u4f46\u8fd9\u4e2a\u9690\u85cf\u684c\u9762\u4e0a\u8fd8\u6ca1\u6709\u5b83\u7684\u7a97\u53e3\u3002';
  }
  if (snapshot.debuggee_state === 'idle') return '\u8fd8\u6ca1\u6709\u542f\u52a8\u8c03\u8bd5\u76ee\u6807\u3002';
  return '\u8fdb\u7a0b\u8fd8\u6ca1\u6709\u7a97\u53e3\u3002\u542f\u52a8\u5e76\u7ee7\u7eed\u8fd0\u884c\u540e\u4f1a\u51fa\u73b0\u5728\u8fd9\u91cc\u3002';
}

export type DesktopWindowHint = {
  hwnd: number;
  visible?: boolean;
  minimized?: boolean;
  area?: number;
  title?: string;
  rect?: { width?: number; height?: number };
};

export type CaptureFailureHint = {
  kind: 'error' | 'degraded';
  text: string;
  reason: string | null;
};

const EMPTY_CAPTURE_HINT =
  '\u8fd9\u4e2a\u7a97\u53e3\u73b0\u5728\u6ca1\u6709\u53ef\u622a\u7684\u533a\u57df\uff08\u6700\u5c0f\u5316\u6216\u5bbd\u9ad8\u4e3a 0\uff09\u3002\u6ca1\u6709\u5207\u8f93\u5165\u684c\u9762\u3002';
const BLANK_CAPTURE_HINT =
  '\u8fd9\u4e00\u5e27\u662f\u9ed1\u7684\u3002\u9690\u85cf\u684c\u9762\u4e0a GPU/DirectX \u7a97\u53e3\u7ecf\u5e38\u622a\u4e0d\u5230\u5185\u5bb9\uff0c\u6ca1\u6709\u5207\u8f93\u5165\u684c\u9762\u3002';
const MOSTLY_BLACK_HINT =
  '\u8fd9\u4e00\u5e27\u51e0\u4e4e\u5168\u9ed1\u3002\u9690\u85cf\u684c\u9762\u4e0a\u7684\u52a0\u901f\u7a97\u53e3\u7ecf\u5e38\u8fd9\u6837\uff0c\u6ca1\u6709\u5207\u8f93\u5165\u684c\u9762\u3002';
const UNIFORM_CAPTURE_HINT =
  '\u8fd9\u4e00\u5e27\u989c\u8272\u51e0\u4e4e\u4e00\u6837\uff0c\u53ef\u80fd\u6ca1\u753b\u51fa\u6765\u3002\u6ca1\u6709\u5207\u8f93\u5165\u684c\u9762\u3002';
const GENERIC_DEGRADED_HINT =
  '\u622a\u5230\u4e86\u753b\u9762\uff0c\u4f46\u8fd9\u4e00\u5e27\u4e0d\u53ef\u9760\u3002\u6ca1\u6709\u5207\u8f93\u5165\u684c\u9762\u3002';

export function windowIsCapturable(row: DesktopWindowHint): boolean {
  const width = Number(row.rect?.width ?? 0);
  const height = Number(row.rect?.height ?? 0);
  const area = Number(row.area ?? width * height);
  return !row.minimized && area > 0 && width > 0 && height > 0;
}

export function windowCaptureRank(row: DesktopWindowHint): [number, number, number, number, number] {
  const width = Number(row.rect?.width ?? 0);
  const height = Number(row.rect?.height ?? 0);
  const area = Number(row.area ?? width * height);
  return [
    Number(windowIsCapturable(row)),
    Number(Boolean(row.visible)),
    Number(!row.minimized),
    area,
    Number(Boolean((row.title ?? '').trim())),
  ];
}

export function pickBestHwnd(windows: DesktopWindowHint[]): number | null {
  const capturable = windows.filter(windowIsCapturable);
  if (!capturable.length) return null;
  const ranked = [...capturable].sort((left, right) => {
    const leftRank = windowCaptureRank(left);
    const rightRank = windowCaptureRank(right);
    for (let index = 0; index < leftRank.length; index += 1) {
      if (rightRank[index] !== leftRank[index]) return rightRank[index] - leftRank[index];
    }
    return 0;
  });
  return ranked[0]?.hwnd ?? null;
}

export function captureDegradedHint(reason: string | null | undefined): string {
  switch (reason) {
    case 'empty_capture':
      return EMPTY_CAPTURE_HINT;
    case 'blank_capture':
      return BLANK_CAPTURE_HINT;
    case 'mostly_black_capture':
      return MOSTLY_BLACK_HINT;
    case 'uniform_capture':
      return UNIFORM_CAPTURE_HINT;
    default:
      return GENERIC_DEGRADED_HINT;
  }
}

export function stripErrorPrefix(raw: string): string {
  return raw.replace(/^Error:\s*/i, '');
}

export function captureFailureHint(raw: string): CaptureFailureHint {
  const text = stripErrorPrefix(raw);
  if (/empty capture area/i.test(text) || /empty_capture/i.test(text)) {
    return { kind: 'degraded', text: EMPTY_CAPTURE_HINT, reason: 'empty_capture' };
  }
  return { kind: 'error', text, reason: null };
}
