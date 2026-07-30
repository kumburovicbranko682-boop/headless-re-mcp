import { bootstrapToken, setTokenForTests } from "./client";

describe("token bootstrap", () => {
  it("removes the token from the visible URL without browser storage", () => {
    history.replaceState({}, "", "/workbench?token=secret-value&x=1#chat");
    expect(bootstrapToken(window.location)).toBe("secret-value");
    expect(window.location.href).not.toContain("secret-value");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    setTokenForTests("");
  });
});
