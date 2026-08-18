import {
  captureDegradedHint,
  captureFailureHint,
  desktopPreviewHint,
  desktopPreviewTitle,
  pickBestHwnd,
  windowIsCapturable,
} from './desktopPreview';

describe('desktop preview copy', () => {
  it('does not treat a paused launch as a missing GUI', () => {
    const snapshot = { available: true, window_count: 0, debuggee_state: 'paused' };
    expect(desktopPreviewTitle(snapshot)).toContain('\u5165\u53e3');
    expect(desktopPreviewHint(snapshot)).toContain('\u7ee7\u7eed\u8fd0\u884c');
  });

  it('waits for the first frame once a window exists', () => {
    expect(desktopPreviewHint({ available: true, window_count: 1, debuggee_state: 'running' })).toContain('\u7b2c\u4e00\u5e27');
  });
});

describe('desktop capture ranking', () => {
  it('skips a visible 0x0 window in favor of a larger hidden one', () => {
    const empty = { hwnd: 1, visible: true, minimized: false, area: 0, title: 'ghost', rect: { width: 0, height: 0 } };
    const hidden = { hwnd: 2, visible: false, minimized: false, area: 480000, title: 'x64dbg', rect: { width: 800, height: 600 } };
    expect(windowIsCapturable(empty)).toBe(false);
    expect(pickBestHwnd([empty, hidden])).toBe(2);
  });

  it('returns null when every window has an empty capture area', () => {
    expect(pickBestHwnd([{ hwnd: 3, visible: true, minimized: false, area: 0, rect: { width: 0, height: 0 } }])).toBeNull();
  });
});

describe('desktop capture copy', () => {
  it('maps empty capture area errors to a Chinese degraded hint', () => {
    const mapped = captureFailureHint('Error: window has empty capture area');
    expect(mapped.kind).toBe('degraded');
    expect(mapped.reason).toBe('empty_capture');
    expect(mapped.text).not.toMatch(/Error:/);
    expect(mapped.text).toContain('\u53ef\u622a');
  });

  it('explains blank PrintWindow frames in Chinese without intern codes', () => {
    const text = captureDegradedHint('blank_capture');
    expect(text).not.toMatch(/blank_capture/);
    expect(text).not.toMatch(/input desktop was not switched/i);
    expect(text).toContain('\u9ed1');
  });
});

describe('desktop preview copy', () => {
  it('does not treat a paused launch as a missing GUI', () => {
    const snapshot = { available: true, window_count: 0, debuggee_state: 'paused' };
    expect(desktopPreviewTitle(snapshot)).toContain('\u5165\u53e3');
    expect(desktopPreviewHint(snapshot)).toContain('\u7ee7\u7eed\u8fd0\u884c');
  });

  it('waits for the first frame once a window exists', () => {
    expect(desktopPreviewHint({ available: true, window_count: 1, debuggee_state: 'running' })).toContain('\u7b2c\u4e00\u5e27');
  });
});
