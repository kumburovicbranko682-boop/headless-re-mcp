import { fireEvent, render, screen } from "@testing-library/react";
import { SessionRail } from "./SessionRail";

describe("SessionRail", () => {
  it("selects a saved session card", () => {
    const picked: string[] = [];
    render(
      <SessionRail
        sessions={[{ id: "s1", binary: "C:\\keep.exe", state: "created", metadata: { restored: true } }]}
        selectedId=""
        unlinkLabel="未关联会话"
        onSelect={(id) => picked.push(id)}
        onRefresh={() => undefined}
      />,
    );
    fireEvent.click(screen.getByText("keep.exe"));
    expect(picked).toEqual(["s1"]);
    expect(screen.getAllByText(/休眠/).length).toBeGreaterThan(0);
  });
});
