import { describe, expect, it } from 'vitest';
import { formatPrice, priceForDisplay } from './money';

describe('server Decimal wire prices', () => {
  it.each([['0', 'Free'], ['5.99', 'USD 5.99'], ['12.99', 'USD 12.99'], ['0.10', 'USD 0.10']])(
    'renders serialized Decimal %s', (price, expected) => {
      const response = JSON.parse(JSON.stringify({ price, currency: 'USD' }));
      expect(formatPrice(response.price, response.currency)).toBe(expected);
    },
  );
  it.each(['', 'free', '1oops', 'NaN', Infinity, -1, undefined])('rejects malformed price %s', (value) => {
    expect(() => priceForDisplay(value)).toThrow('Invalid decimal price');
  });
});
