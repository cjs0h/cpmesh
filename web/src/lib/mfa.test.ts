import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { ApiError, setReauthHandler } from './api';
import { getAccessToken, getRefreshToken, setTokens } from './auth';
import {
  addPasskey,
  base64urlToBuffer,
  bufferToBase64url,
  challengeFromBody,
  challengeFromStatus,
  completeSignIn,
  createPasskey,
  defaultPasskeyName,
  errorMessage,
  getPasskeyAssertion,
  isCancellation,
  normalizeOtp,
  PasskeyError,
  passkeysSupported,
  recoveryCodesText,
  sessionTransport,
  svgDataUrl,
  ticketTransport,
  toCreationOptions,
  verifyEmailCode,
  verifyFactor,
  verifyWithPasskey,
  type CreationOptionsJSON,
  type MfaStatus,
  type RequestOptionsJSON,
} from './mfa';
import { jsonResponse } from '../test/setup';

const fetchMock = () => fetch as unknown as Mock;

const bytes = (...values: number[]) => new Uint8Array(values).buffer;
const text = (value: string) => new TextEncoder().encode(value).buffer;
const view = (buffer: unknown) => Array.from(new Uint8Array(buffer as ArrayBuffer));

/** Installs a fake WebAuthn API; returns the `create`/`get` mocks. */
function stubWebAuthn() {
  const create = vi.fn();
  const get = vi.fn();
  vi.stubGlobal('PublicKeyCredential', class {});
  vi.stubGlobal('navigator', { userAgent: 'test', credentials: { create, get } });
  return { create, get };
}

const creationOptions: CreationOptionsJSON = {
  challenge: 'AQID',
  rp: { id: 'cpmesh.test', name: 'cpmesh' },
  user: { id: 'dXNlcg', name: 'alice', displayName: 'Alice' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 60000,
  attestation: 'none',
  excludeCredentials: [{ type: 'public-key', id: 'BAUG', transports: ['internal'] }],
  authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
};

const requestOptions: RequestOptionsJSON = {
  challenge: '-_8',
  rpId: 'cpmesh.test',
  allowCredentials: [{ type: 'public-key', id: 'BAUG' }],
  userVerification: 'preferred',
  timeout: 60000,
};

function status(overrides: Partial<MfaStatus> = {}): MfaStatus {
  return {
    required: true,
    enabled: false,
    totp: false,
    passkeys: [],
    recovery_codes_remaining: 0,
    passkeys_available: true,
    session_verified: null,
    recent_auth: null,
    has_password: true,
    stage: null,
    email_code_required: false,
    ...overrides,
  };
}

beforeEach(() => {
  fetchMock().mockReset();
  setReauthHandler(null);
});

describe('base64url', () => {
  it('encodes without padding using the URL-safe alphabet', () => {
    expect(bufferToBase64url(bytes())).toBe('');
    expect(bufferToBase64url(bytes(1))).toBe('AQ');
    expect(bufferToBase64url(bytes(1, 2))).toBe('AQI');
    expect(bufferToBase64url(bytes(1, 2, 3))).toBe('AQID');
    // 0xfb 0xff 0xfe is "+//+" in standard base64
    expect(bufferToBase64url(bytes(0xfb, 0xff, 0xfe))).toBe('-__-');
  });

  it('encodes only the viewed bytes of a typed array', () => {
    const backing = new Uint8Array([9, 1, 2, 3, 9]);
    expect(bufferToBase64url(backing.subarray(1, 4))).toBe('AQID');
  });

  it('decodes with or without padding and from either alphabet', () => {
    expect(view(base64urlToBuffer('AQID'))).toEqual([1, 2, 3]);
    expect(view(base64urlToBuffer('AQI'))).toEqual([1, 2]);
    expect(view(base64urlToBuffer('AQ=='))).toEqual([1]);
    expect(view(base64urlToBuffer('-__-'))).toEqual([0xfb, 0xff, 0xfe]);
    expect(view(base64urlToBuffer('+//+'))).toEqual([0xfb, 0xff, 0xfe]);
    expect(view(base64urlToBuffer(''))).toEqual([]);
  });

  it('round-trips arbitrary bytes', () => {
    const all = new Uint8Array(256).map((_, i) => i);
    expect(view(base64urlToBuffer(bufferToBase64url(all)))).toEqual(Array.from(all));
  });
});

describe('WebAuthn options', () => {
  it('turns the base64url fields of creation options into buffers', () => {
    const options = toCreationOptions(creationOptions);
    expect(view(options.challenge)).toEqual([1, 2, 3]);
    expect(view(options.user.id)).toEqual(Array.from(new TextEncoder().encode('user')));
    expect(options.user.name).toBe('alice');
    expect(options.rp).toEqual({ id: 'cpmesh.test', name: 'cpmesh' });
    expect(options.excludeCredentials).toHaveLength(1);
    expect(view(options.excludeCredentials![0].id)).toEqual([4, 5, 6]);
    expect(options.excludeCredentials![0].transports).toEqual(['internal']);
    expect(options.authenticatorSelection).toEqual({ residentKey: 'preferred', userVerification: 'preferred' });
  });

  it('reports passkey support only when the browser has WebAuthn', () => {
    vi.stubGlobal('navigator', { credentials: undefined });
    expect(passkeysSupported()).toBe(false);
    stubWebAuthn();
    expect(passkeysSupported()).toBe(true);
  });
});

describe('createPasskey', () => {
  it('passes buffers to navigator.credentials.create and serializes the credential', async () => {
    const { create } = stubWebAuthn();
    const getTransports = vi.fn(() => ['internal', 'hybrid']);
    create.mockResolvedValue({
      id: 'cred-1',
      rawId: bytes(0xfb, 0xff),
      type: 'public-key',
      response: { clientDataJSON: text('{"type":"webauthn.create"}'), attestationObject: bytes(1, 2, 3), getTransports },
    });

    const credential = await createPasskey(creationOptions);

    const { publicKey } = create.mock.calls[0][0];
    expect(view(publicKey.challenge)).toEqual([1, 2, 3]);
    expect(view(publicKey.user.id)).toEqual(Array.from(new TextEncoder().encode('user')));
    expect(view(publicKey.excludeCredentials[0].id)).toEqual([4, 5, 6]);
    expect(credential).toEqual({
      id: 'cred-1',
      rawId: '-_8',
      type: 'public-key',
      response: {
        clientDataJSON: bufferToBase64url(text('{"type":"webauthn.create"}')),
        attestationObject: 'AQID',
        transports: ['internal', 'hybrid'],
      },
    });
    expect(getTransports).toHaveBeenCalled();
  });

  it('sends no transports when the browser cannot list them', async () => {
    const { create } = stubWebAuthn();
    create.mockResolvedValue({ id: 'c', rawId: bytes(1), type: 'public-key', response: { clientDataJSON: bytes(2), attestationObject: bytes(3) } });
    expect((await createPasskey(creationOptions)).response.transports).toEqual([]);
  });

  it('reports a dismissed prompt as a cancellation', async () => {
    const { create } = stubWebAuthn();
    create.mockRejectedValue(new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'));

    const error = await createPasskey(creationOptions).catch((e) => e);

    expect(error).toBeInstanceOf(PasskeyError);
    expect(error.cancelled).toBe(true);
    expect(isCancellation(error)).toBe(true);
  });

  it('explains a passkey that is already registered on this device', async () => {
    const { create } = stubWebAuthn();
    create.mockRejectedValue(new DOMException('excluded', 'InvalidStateError'));

    const error = await createPasskey(creationOptions).catch((e) => e);

    expect(error).toBeInstanceOf(PasskeyError);
    expect(error.cancelled).toBe(false);
    expect(error.message).toMatch(/already has a passkey/);
  });

  it('fails clearly without WebAuthn', async () => {
    vi.stubGlobal('navigator', {});
    await expect(createPasskey(creationOptions)).rejects.toThrow(/doesn't support passkeys/);
  });
});

describe('getPasskeyAssertion', () => {
  it('passes buffers to navigator.credentials.get and serializes the assertion', async () => {
    const { get } = stubWebAuthn();
    get.mockResolvedValue({
      id: 'cred-1',
      rawId: bytes(4, 5, 6),
      type: 'public-key',
      response: { clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: text('user') },
    });

    const assertion = await getPasskeyAssertion(requestOptions);

    const { publicKey } = get.mock.calls[0][0];
    expect(view(publicKey.challenge)).toEqual([0xfb, 0xff]);
    expect(publicKey.rpId).toBe('cpmesh.test');
    expect(view(publicKey.allowCredentials[0].id)).toEqual([4, 5, 6]);
    expect(publicKey.allowCredentials[0]).not.toHaveProperty('transports');
    expect(assertion).toEqual({
      id: 'cred-1',
      rawId: 'BAUG',
      type: 'public-key',
      response: { clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw', userHandle: 'dXNlcg' },
    });
  });

  it('sends a null user handle when the authenticator returns none', async () => {
    const { get } = stubWebAuthn();
    get.mockResolvedValue({
      id: 'c',
      rawId: bytes(1),
      type: 'public-key',
      response: { clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: null },
    });
    expect((await getPasskeyAssertion(requestOptions)).response.userHandle).toBeNull();
  });

  it('treats a prompt that returned nothing as cancelled', async () => {
    const { get } = stubWebAuthn();
    get.mockResolvedValue(null);
    const error = await getPasskeyAssertion(requestOptions).catch((e) => e);
    expect(error).toBeInstanceOf(PasskeyError);
    expect(error.cancelled).toBe(true);
  });
});

describe('ticketTransport', () => {
  it('authenticates with the sign-in ticket, not the stored session', async () => {
    setTokens('session-access', 'session-refresh');
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { access_token: 'a', refresh_token: 'r' }));

    const send = ticketTransport(() => 'ticket-1');
    await verifyFactor(send, { method: 'totp', code: '123456' });

    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/mfa/verify');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer ticket-1');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body)).toEqual({ method: 'totp', code: '123456' });
  });

  it('reads the current ticket for every request', async () => {
    let ticket = 'first';
    const send = ticketTransport(() => ticket);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { mfa_token: 'second' }))
      .mockResolvedValueOnce(jsonResponse(200, {}));

    ticket = await verifyEmailCode(send, '123456');
    await send('/api/mfa');

    expect(ticket).toBe('second');
    expect(fetchMock().mock.calls[0][1].headers.Authorization).toBe('Bearer first');
    expect(fetchMock().mock.calls[1][1].headers.Authorization).toBe('Bearer second');
  });

  it('throws ApiError with the code and body, without refreshing on 401', async () => {
    setTokens('session-access', 'session-refresh');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(429, { error: 'Too many failed attempts.', code: 'mfa_locked' }))
      .mockResolvedValueOnce(jsonResponse(401, { error: 'that code is not right' }));
    const send = ticketTransport(() => 'ticket');

    const locked = await verifyFactor(send, { method: 'totp', code: '000000' }).catch((e) => e);
    expect(locked).toBeInstanceOf(ApiError);
    expect(locked.status).toBe(429);
    expect(locked.code).toBe('mfa_locked');
    expect(locked.data).toEqual({ error: 'Too many failed attempts.', code: 'mfa_locked' });

    await expect(verifyFactor(send, { method: 'totp', code: '000000' })).rejects.toThrow('that code is not right');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(getAccessToken()).toBe('session-access');
  });
});

describe('sessionTransport', () => {
  it('reports a wrong code the server marks as such without checking the session', async () => {
    setTokens('access', 'refresh');
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'that code is not right', code: 'invalid_code' }));

    await expect(verifyFactor(sessionTransport, { method: 'totp', code: '000000' })).rejects.toThrow('that code is not right');

    expect(fetchMock().mock.calls.map(([url]) => url)).toEqual(['/api/mfa/verify']);
    expect(getAccessToken()).toBe('access');
  });

  it('does not send a wrong code twice', async () => {
    setTokens('access', 'refresh');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'that code is not right' }))
      // The session itself is fine
      .mockResolvedValueOnce(jsonResponse(200, { enabled: true }));

    await expect(verifyFactor(sessionTransport, { method: 'totp', code: '000000' })).rejects.toThrow('that code is not right');

    const urls = fetchMock().mock.calls.map(([url]) => url);
    expect(urls).toEqual(['/api/mfa/verify', '/api/mfa']);
    expect(getAccessToken()).toBe('access');
  });

  it('sends again after refreshing an expired session', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token; sign in again' }))
      // api() refreshes while checking the session
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token; sign in again' }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'fresh', refresh_token: 'refresh-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { enabled: true }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'verified', refresh_token: 'refresh-3' }));

    const result = await verifyFactor(sessionTransport, { method: 'totp', code: '123456' });

    expect(result).toEqual({ access_token: 'verified', refresh_token: 'refresh-3' });
    const last = fetchMock().mock.calls.at(-1)!;
    expect(last[0]).toBe('/api/mfa/verify');
    expect(last[1].headers.Authorization).toBe('Bearer fresh');
  });

  it('asks the user to confirm on reauth_required, then sends again', async () => {
    setTokens('stale', 'refresh-1');
    const handler = vi.fn(async () => {
      setTokens('confirmed', 'refresh-2');
      return true;
    });
    setReauthHandler(handler);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }))
      .mockResolvedValueOnce(jsonResponse(200, { secret: 'ABC', otpauth_uri: 'otpauth://x', qr_svg: null }));

    const setup = await sessionTransport('/api/mfa/totp/setup', { method: 'POST' });

    expect(setup).toEqual({ secret: 'ABC', otpauth_uri: 'otpauth://x', qr_svg: null });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchMock().mock.calls[1][1].headers.Authorization).toBe('Bearer confirmed');
  });

  it('gives up when the user cancels the confirmation', async () => {
    setTokens('stale', 'refresh-1');
    setReauthHandler(async () => false);
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }));

    const error = (await sessionTransport('/api/mfa/totp/setup', { method: 'POST' }).catch((e) => e)) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('reauth_required');
    expect(isCancellation(error)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('asks only once when the server still wants a confirmation', async () => {
    setTokens('stale', 'refresh-1');
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    fetchMock().mockResolvedValue(jsonResponse(403, { error: 'Confirm it with your second factor.', code: 'reauth_required' }));

    await expect(sessionTransport('/api/mfa/totp', { method: 'DELETE' })).rejects.toThrow('Confirm it with your second factor.');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe('passkey ceremonies', () => {
  it('registers a passkey: options, create, register', async () => {
    const { create } = stubWebAuthn();
    create.mockResolvedValue({ id: 'c', rawId: bytes(1), type: 'public-key', response: { clientDataJSON: bytes(2), attestationObject: bytes(3) } });
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { options: creationOptions, challenge_token: 'challenge-1' }))
      .mockResolvedValueOnce(jsonResponse(200, { passkey: { id: 'p1' }, access_token: 'a', refresh_token: 'r', recovery_codes: ['x'] }));

    const result = await addPasskey(ticketTransport(() => 'ticket'), 'MacBook');

    expect(result.recovery_codes).toEqual(['x']);
    const [url, init] = fetchMock().mock.calls[1];
    expect(url).toBe('/api/mfa/passkeys');
    expect(JSON.parse(init.body)).toEqual({
      challenge_token: 'challenge-1',
      name: 'MacBook',
      credential: { id: 'c', rawId: 'AQ', type: 'public-key', response: { clientDataJSON: 'Ag', attestationObject: 'Aw', transports: [] } },
    });
  });

  it('verifies with a passkey: options, get, verify', async () => {
    const { get } = stubWebAuthn();
    get.mockResolvedValue({
      id: 'c',
      rawId: bytes(1),
      type: 'public-key',
      response: { clientDataJSON: bytes(2), authenticatorData: bytes(3), signature: bytes(4), userHandle: null },
    });
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { options: requestOptions, challenge_token: 'challenge-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'a', refresh_token: 'r' }));

    await verifyWithPasskey(ticketTransport(() => 'ticket'));

    expect(fetchMock().mock.calls[0][0]).toBe('/api/mfa/verify/options');
    const [url, init] = fetchMock().mock.calls[1];
    expect(url).toBe('/api/mfa/verify');
    expect(JSON.parse(init.body)).toEqual({
      method: 'webauthn',
      challenge_token: 'challenge-2',
      credential: { id: 'c', rawId: 'AQ', type: 'public-key', response: { clientDataJSON: 'Ag', authenticatorData: 'Aw', signature: 'BA', userHandle: null } },
    });
  });

  it('does not call the server again when the prompt is dismissed', async () => {
    const { get } = stubWebAuthn();
    get.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'));
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { options: requestOptions, challenge_token: 't' }));

    await expect(verifyWithPasskey(ticketTransport(() => 'ticket'))).rejects.toBeInstanceOf(PasskeyError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('second step of a sign-in', () => {
  it('reads the mfa_required body', () => {
    expect(
      challengeFromBody({
        error: 'Two-factor authentication is required',
        code: 'mfa_required',
        mfa_token: 'ticket',
        stage: 'enroll',
        methods: ['totp', 'webauthn', 'sms'],
        email_code_required: true,
        email_hint: 'a***@example.com',
        passkeys_available: true,
      }),
    ).toEqual({
      mfa_token: 'ticket',
      stage: 'enroll',
      methods: ['totp', 'webauthn'],
      email_code_required: true,
      email_hint: 'a***@example.com',
      passkeys_available: true,
    });
  });

  it('ignores other errors', () => {
    expect(challengeFromBody({ error: 'invalid credentials' })).toBeNull();
    expect(challengeFromBody({ error: 'x', code: 'account_suspended' })).toBeNull();
    expect(challengeFromBody({ error: 'x', code: 'mfa_required', enrolled: false })).toBeNull();
  });

  it('builds the verify methods from the status of an SSO sign-in', () => {
    const challenge = challengeFromStatus(
      'ticket',
      status({
        stage: 'verify',
        enabled: true,
        totp: true,
        passkeys: [{ id: 'p', name: 'Mac', created_at: '', last_used_at: null, backup_eligible: true }],
        recovery_codes_remaining: 4,
      }),
    );
    expect(challenge).toEqual({
      mfa_token: 'ticket',
      stage: 'verify',
      methods: ['totp', 'webauthn', 'recovery'],
      email_code_required: false,
      email_hint: null,
      passkeys_available: true,
    });
  });

  it('leaves out passkeys the server cannot check and spent recovery codes', () => {
    const challenge = challengeFromStatus(
      'ticket',
      status({
        stage: 'verify',
        enabled: true,
        passkeys: [{ id: 'p', name: 'Mac', created_at: '', last_used_at: null, backup_eligible: false }],
        passkeys_available: false,
        totp: true,
      }),
    );
    expect(challenge.methods).toEqual(['totp']);
  });

  it('offers what can be set up when enrolling', () => {
    expect(challengeFromStatus('t', status({ stage: 'enroll' })).methods).toEqual(['totp', 'webauthn']);
    expect(challengeFromStatus('t', status({ stage: 'enroll', passkeys_available: false })).methods).toEqual(['totp']);
    expect(challengeFromStatus('t', status({ stage: 'enroll', email_code_required: true })).email_code_required).toBe(true);
  });
});

describe('completeSignIn', () => {
  it('stores the session for this browser', async () => {
    await expect(completeSignIn({ access_token: 'a', refresh_token: 'r' }, null)).resolves.toBeNull();
    expect(getAccessToken()).toBe('a');
    expect(getRefreshToken()).toBe('r');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('hands the sign-in to the desktop app without storing it', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { code: 'one time/code' }));
    const app = { clientRedirect: 'cpmesh://auth/callback', codeChallenge: 'c'.repeat(43) };

    const url = await completeSignIn({ access_token: 'new-access', refresh_token: 'new-refresh' }, app);

    expect(url).toBe('cpmesh://auth/callback?code=one%20time%2Fcode');
    const [path, init] = fetchMock().mock.calls[0];
    expect(path).toBe('/api/auth/native-code');
    expect(init.headers.Authorization).toBe('Bearer new-access');
    expect(JSON.parse(init.body)).toEqual({ code_challenge: 'c'.repeat(43) });
    expect(getAccessToken()).toBeNull();
  });

  it('appends the code to a redirect that already has a query', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { code: 'abc' }));
    const url = await completeSignIn({ access_token: 'a', refresh_token: 'r' }, { clientRedirect: 'cpmesh://auth/callback?x=1', codeChallenge: 'c' });
    expect(url).toBe('cpmesh://auth/callback?x=1&code=abc');
  });

  it('reports a failed handoff', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(400, { error: 'invalid code_challenge' }));
    await expect(completeSignIn({ access_token: 'a', refresh_token: 'r' }, { clientRedirect: 'cpmesh://cb', codeChallenge: 'x' })).rejects.toThrow(
      'invalid code_challenge',
    );
  });
});

describe('helpers', () => {
  it('keeps the digits of a typed or pasted code', () => {
    expect(normalizeOtp('123 456')).toBe('123456');
    expect(normalizeOtp('12-34-56-78')).toBe('123456');
    expect(normalizeOtp('abc')).toBe('');
  });

  it('wraps SVG markup in a base64 data URL', () => {
    const url = svgDataUrl('<svg xmlns="http://www.w3.org/2000/svg"><title>é</title></svg>');
    expect(url.startsWith('data:image/svg+xml;base64,')).toBe(true);
    const decoded = new TextDecoder().decode(Uint8Array.from(atob(url.split(',')[1]), (c) => c.charCodeAt(0)));
    expect(decoded).toBe('<svg xmlns="http://www.w3.org/2000/svg"><title>é</title></svg>');
  });

  it('writes the recovery codes file', () => {
    const file = recoveryCodesText(['aaaa-bbbb-cccc-dddd', 'eeee-ffff-gggg-hhhh'], 'alice@example.com');
    expect(file.split('\n')[0]).toBe('cpmesh recovery codes for alice@example.com');
    expect(file).toContain('\naaaa-bbbb-cccc-dddd\neeee-ffff-gggg-hhhh\n');
  });

  it('suggests a passkey name from the platform', () => {
    expect(defaultPasskeyName('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15')).toBe('Mac');
    expect(defaultPasskeyName('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')).toBe('iPhone');
    expect(defaultPasskeyName('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe('Windows');
    expect(defaultPasskeyName('Mozilla/5.0 (Linux; Android 15; Pixel 9)')).toBe('Android');
    expect(defaultPasskeyName('curl/8')).toBe('Passkey');
  });

  it('starts error messages with a capital letter', () => {
    expect(errorMessage(new Error('that code is not right'))).toBe('That code is not right');
    expect(errorMessage('nope', 'Fallback')).toBe('Fallback');
  });

  it('tells cancellations apart from failures', () => {
    expect(isCancellation(new ApiError('Confirm', 403, { code: 'reauth_required' }))).toBe(true);
    expect(isCancellation(new ApiError('nope', 403, { code: 'mfa_required' }))).toBe(false);
    expect(isCancellation(new PasskeyError('closed', true))).toBe(true);
    expect(isCancellation(new PasskeyError('failed'))).toBe(false);
    expect(isCancellation(new Error('x'))).toBe(false);
  });
});
