import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <main className="error-boundary">
        <h1>{"\u754c\u9762\u51fa\u9519"}</h1>
        <p>{"\u6253\u5f00\u4f1a\u8bdd\u65f6\u5982\u679c\u6574\u9875\u53d8\u9ed1\uff0c\u5c31\u662f\u8fd9\u91cc\u63a5\u4f4f\u4e86\u6e32\u67d3\u5f02\u5e38\u3002"}</p>
        <pre>{this.state.error.message}</pre>
        <button type="button" onClick={() => this.setState({ error: null })}>{"\u56de\u5230\u5de5\u4f5c\u53f0"}</button>
      </main>
    );
  }
}
