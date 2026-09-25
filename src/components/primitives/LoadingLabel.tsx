export function LoadingLabel({ children }: Readonly<{ children: string }>) {
  return (
    <>
      <span className="loading-spinner" role="presentation" aria-hidden="true" />
      <span role="status" aria-live="polite">{children}</span>
    </>
  );
}
