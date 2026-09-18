export function LoadingLabel({ children }: Readonly<{ children: string }>) {
  return (
    <>
      <span className="loading-spinner" aria-hidden="true" />
      <span>{children}</span>
    </>
  );
}
