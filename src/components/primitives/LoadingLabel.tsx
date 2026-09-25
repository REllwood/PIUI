// Loading copy sits inside buttons and existing status regions, so it must not
// open a live region of its own; the surrounding control or region announces it.
export function LoadingLabel({ children }: Readonly<{ children: string }>) {
  return (
    <>
      <span className="loading-spinner" aria-hidden="true" />
      <span>{children}</span>
    </>
  );
}
