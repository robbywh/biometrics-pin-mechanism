// Design tokens (single source for colour, spacing, radius, type).
export const color = {
  bg: '#0B1020',
  surface: '#151B2E',
  surfaceAlt: '#1D2540',
  text: '#F4F6FB',
  textDim: '#9AA3BC',
  primary: '#4C8DFF',
  primaryText: '#08122B',
  danger: '#FF6B6B',
  warn: '#FFB84D',
  ok: '#4ADE80',
  border: '#2A3358',
};
export const space = { xs: 4, sm: 8, md: 16, lg: 24, xl: 32 } as const;
export const radius = { sm: 8, md: 14, lg: 24, pill: 999 } as const;
export const font = { body: 16, small: 13, title: 28, h2: 20, mono: 18 } as const;
export const MIN_TARGET = 56; // accessible touch target
