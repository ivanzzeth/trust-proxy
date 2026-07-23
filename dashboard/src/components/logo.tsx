// The trust-proxy mark: outbound traffic flowing through a trust checkpoint
// (the center diamond) inside a shield — i.e. egress passing an inspection
// gate. Monochrome (currentColor) so it inherits the surrounding text color;
// reused in the sidebar brand. The favicon (public/logo.svg) mirrors this in
// the jade accent.
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path
        d="M16 2.5 26.5 6.2V15C26.5 22.4 21.8 27.6 16 29.5 10.2 27.6 5.5 22.4 5.5 15V6.2Z"
        fill="currentColor"
        opacity="0.14"
      />
      <path
        d="M16 2.5 26.5 6.2V15C26.5 22.4 21.8 27.6 16 29.5 10.2 27.6 5.5 22.4 5.5 15V6.2Z"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path d="M7.5 16H12.3" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <path d="M19.7 16H24.5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <path d="M16 11.8 20.2 16 16 20.2 11.8 16Z" fill="currentColor" />
    </svg>
  );
}
