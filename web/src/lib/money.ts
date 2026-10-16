/** The server sends Decimal as a string. Numbers are accepted for existing view
 * models/forms only; conversion is for display, never a change to the wire format. */
export function priceForDisplay(value: unknown): number {
  if ((typeof value !== 'string' && typeof value !== 'number')
      || (typeof value === 'string' && !/^\d+(?:\.\d+)?$/.test(value))) {
    throw new Error('Invalid decimal price');
  }
  const price = Number(value);
  if (!Number.isFinite(price) || price < 0) throw new Error('Invalid decimal price');
  return price;
}

export function formatPrice(value: string | number | null, currency: string | null): string {
  if (value === null) return 'Free';
  const price = priceForDisplay(value);
  return price === 0 ? 'Free' : `${currency ?? ''} ${price.toFixed(2)}`.trim();
}
