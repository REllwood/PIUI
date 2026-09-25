import { useId } from 'react';

// Geometry and colours match .github/media/piui-mark.svg: a graphite tile holding a
// luminous π. The tile colours come from the dark theme surfaces and the π from its
// accent, so the mark reads the same whichever theme surrounds it.
const TILE =
  'M327.68 0c64.52 0 96.78 0 121.42 12.56a115.2 115.2 0 0 1 50.34 50.34c12.56 24.64 12.56 56.9 12.56 121.42L512 327.68c0 64.52 0 96.78 -12.56 121.42a115.2 115.2 0 0 1 -50.34 50.34c-24.64 12.56 -56.9 12.56 -121.42 12.56L184.32 512c-64.52 0 -96.78 0 -121.42 -12.56a115.2 115.2 0 0 1 -50.34 -50.34c-12.56 -24.64 -12.56 -56.9 -12.56 -121.42L0 184.32c0 -64.52 0 -96.78 12.56 -121.42a115.2 115.2 0 0 1 50.34 -50.34c24.64 -12.56 56.9 -12.56 121.42 -12.56Z';
const RIM =
  'M328.58 1.5c63.68 0 95.52 0 119.84 12.39a113.7 113.7 0 0 1 49.69 49.69c12.39 24.32 12.39 56.16 12.39 119.84L510.5 328.58c0 63.68 0 95.52 -12.39 119.84a113.7 113.7 0 0 1 -49.69 49.69c-24.32 12.39 -56.16 12.39 -119.84 12.39L183.42 510.5c-63.68 0 -95.52 0 -119.84 -12.39a113.7 113.7 0 0 1 -49.69 -49.69c-12.39 -24.32 -12.39 -56.16 -12.39 -119.84L1.5 183.42c0 -63.68 0 -95.52 12.39 -119.84a113.7 113.7 0 0 1 49.69 -49.69c24.32 -12.39 56.16 -12.39 119.84 -12.39Z';
const PI =
  'M133 127H379A29 29 0 0 1 379 185H133A29 29 0 0 1 133 127ZM217 156L217 258.41A279 279 0 0 1 198.47 358.39A29 29 0 0 1 144.32 337.61A221 221 0 0 0 159 258.41L159 156ZM349 156L349 277.69A42.4 42.4 0 0 0 384.04 319.44A29 29 0 0 1 373.96 376.56A100.4 100.4 0 0 1 291 277.69L291 156ZM160 184L160 195L159 195A10 10 0 0 0 149 185L149 184ZM216 184L227 184L227 185A10 10 0 0 0 217 195L216 195ZM292 184L292 195L291 195A10 10 0 0 0 281 185L281 184ZM348 184L359 184L359 185A10 10 0 0 0 349 195L348 195Z';

// Decorative beside visible "PIUI" text by default. Pass a label only where the mark
// stands alone and has to name the product itself. Colours are SVG presentation
// attributes rather than inline styles, which the content security policy forbids. The
// edge path is themed from CSS: the graphite tile needs a hairline to separate it from
// dark surfaces but already stands out on light ones.
export function BrandMark({
  size = 34,
  label,
  className,
}: Readonly<{ size?: number; label?: string; className?: string }>) {
  // Gradient and filter ids are document-global, so each instance needs its own.
  const prefix = `piui-mark-${useId().replace(/[^A-Za-z0-9_-]/gu, '')}`;
  const tile = `${prefix}-tile`;
  const sheen = `${prefix}-sheen`;
  const ambient = `${prefix}-ambient`;
  const rim = `${prefix}-rim`;
  const glyph = `${prefix}-glyph`;
  const glow = `${prefix}-glow`;
  const naming = label
    ? ({ role: 'img', 'aria-label': label } as const)
    : ({ 'aria-hidden': true } as const);
  return (
    <svg
      className={className ? `brand-mark ${className}` : 'brand-mark'}
      width={size}
      height={size}
      viewBox="0 0 512 512"
      focusable="false"
      {...naming}
    >
      <defs>
        <linearGradient id={tile} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#202521" />
          <stop offset=".55" stopColor="#171b18" />
          <stop offset="1" stopColor="#0f1210" />
        </linearGradient>
        <radialGradient id={sheen} cx=".5" cy="0" r=".75" gradientTransform="matrix(1 0 0 .7 0 0)">
          <stop offset="0" stopColor="#f3f6f2" stopOpacity=".09" />
          <stop offset="1" stopColor="#f3f6f2" stopOpacity="0" />
        </radialGradient>
        <radialGradient id={ambient}>
          <stop offset="0" stopColor="#c8f36b" stopOpacity=".13" />
          <stop offset="1" stopColor="#c8f36b" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={rim} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#f3f6f2" stopOpacity=".2" />
          <stop offset=".4" stopColor="#f3f6f2" stopOpacity=".06" />
          <stop offset="1" stopColor="#f3f6f2" stopOpacity=".03" />
        </linearGradient>
        <linearGradient id={glyph} gradientUnits="userSpaceOnUse" x1="0" y1="127" x2="0" y2="377">
          <stop offset="0" stopColor="#d7f499" />
          <stop offset=".45" stopColor="#c8f36b" />
          <stop offset="1" stopColor="#b4dc5a" />
        </linearGradient>
        <filter id={glow} x="0" y="0" width="512" height="512" filterUnits="userSpaceOnUse">
          <feGaussianBlur stdDeviation="16" />
        </filter>
      </defs>
      <path d={TILE} fill={`url(#${tile})`} />
      <path d={TILE} fill={`url(#${sheen})`} />
      <circle cx="256" cy="266" r="215" fill={`url(#${ambient})`} />
      <path className="brand-mark__edge" d={TILE} />
      <path d={RIM} fill="none" stroke={`url(#${rim})`} strokeWidth="3" />
      <path d={PI} fill="#c8f36b" opacity=".34" filter={`url(#${glow})`} />
      <path d={PI} fill={`url(#${glyph})`} />
    </svg>
  );
}
