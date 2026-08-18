import { fireEvent, render, screen } from "@testing-library/react";
import { ApprovalModeControl } from "./ApprovalModeControl";

describe("ApprovalModeControl", () => {
  it("shows the current mode on the pill and opens the two Codex options", () => {
    const onChange = vi.fn();
    render(<ApprovalModeControl mode="full_access" onChange={onChange} />);

    fireEvent.click(screen.getByRole("button", { name: "完全访问" }));
    expect(screen.getByText("应如何批准 Agent 操作？")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /请求批准/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /完全访问权限/ })).toBeInTheDocument();
    expect(screen.queryByText("帮我批准")).toBeNull();
    expect(screen.queryByText(/仅对检测到的风险操作/)).toBeNull();

    fireEvent.click(screen.getByRole("option", { name: /请求批准/ }));
    expect(onChange).toHaveBeenCalledWith("request");
  });

  it("explains the two modes from 了解更多", () => {
    render(<ApprovalModeControl mode="request" onChange={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "请求批准" }));
    fireEvent.click(screen.getByRole("button", { name: "了解更多" }));
    expect(screen.getByText(/没有「帮我批准」中间档/)).toBeInTheDocument();
  });
});
