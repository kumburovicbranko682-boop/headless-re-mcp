import { act, fireEvent, render } from "@testing-library/react";
import { ChatMessage } from "./ChatMessage";

// jsdom reports scrollHeight as 0, so nothing ever "overflows". Force a tall
// body so the "展开全部" affordance renders and the clamp logic is exercised.
let originalScrollHeight: PropertyDescriptor | undefined;

beforeAll(() => {
  originalScrollHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
  Object.defineProperty(HTMLElement.prototype, "scrollHeight", {
    configurable: true,
    get() {
      return 400;
    },
  });
});

afterAll(() => {
  if (originalScrollHeight) {
    Object.defineProperty(HTMLElement.prototype, "scrollHeight", originalScrollHeight);
  } else {
    delete (HTMLElement.prototype as unknown as { scrollHeight?: unknown }).scrollHeight;
  }
});

describe("ChatMessage streaming expand", () => {
  it("keeps a streaming reply expanded when more tokens append", async () => {
    const base = "line ".repeat(80);
    const view = render(<ChatMessage role="assistant" content={base} streaming />);
    await act(async () => {});

    fireEvent.click(view.getByText("展开全部"));
    // The expand button disappears once expanded.
    expect(view.queryByText("展开全部")).toBeNull();

    // Next streamed delta extends the content; the reply must stay open.
    view.rerender(<ChatMessage role="assistant" content={base + "and more text"} streaming />);
    await act(async () => {});
    expect(view.queryByText("展开全部")).toBeNull();
  });

  it("collapses again when the element is reused for a different message", async () => {
    const base = "line ".repeat(80);
    const view = render(<ChatMessage role="assistant" content={base} streaming />);
    await act(async () => {});

    fireEvent.click(view.getByText("展开全部"));
    expect(view.queryByText("展开全部")).toBeNull();

    // A non-append replacement is a genuinely new message; collapse it.
    view.rerender(<ChatMessage role="assistant" content={"completely unrelated body ".repeat(20)} streaming />);
    await act(async () => {});
    expect(view.queryByText("展开全部")).not.toBeNull();
  });
});
