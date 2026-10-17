// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, describe, expect, it } from 'vitest';
import McpGuide from './McpGuide.svelte';
import { cleanup, pageText, render } from '../../test/dom';

afterEach(cleanup);

describe('MCP guide', () => {
  it.each([false, true])('describes browser sign-in and never mentions a password (inApp: %s)', (inApp) => {
    render(McpGuide, { inApp });

    const text = pageText();
    for (const banned of [/password/i, /\btotp\b/i, /authenticator/i, /6-digit/i, /CPMESH_USERNAME/, /CPMESH_PASSWORD/]) {
      expect(text, String(banned)).not.toMatch(banned);
    }
    expect(text).toContain('Approve it in your browser');
    expect(text).toContain('https://cpmesh.com/activate');
    expect(text).toContain('8-digit pairing code');
    expect(text).toContain('CPMESH_SERVER_URL');
    expect(text).toContain('13 tools');
  });
});
