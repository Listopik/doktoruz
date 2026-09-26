const crypto = require('crypto');
const { query } = require('./db');

function normalizePhone(value) {
  let s = String(value || '').replace(/\D/g, '');

  if (s.startsWith('8')) {
    s = '998' + s.slice(1);
  }

  if (!s.startsWith('998') && s.length === 9) {
    s = '998' + s;
  }

  return s;
}

function e164(value) {
  const s = normalizePhone(value);
  return s ? '+' + s : '';
}

function b64url(value) {
  return Buffer
    .from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function ub64url(value) {
  return Buffer.from(
    value
      .replace(/-/g, '+')
      .replace(/_/g, '/'),
    'base64'
  );
}

function sign(payload) {
  const raw = b64url(
    JSON.stringify(payload)
  );

  const secret =
    process.env.SESSION_SECRET ||
    'dev-only-secret';

  const signature =
    crypto
      .createHmac('sha256', secret)
      .update(raw)
      .digest();

  return (
    raw +
    '.' +
    b64url(signature)
  );
}

function verify(token) {
  try {
    const parts =
      String(token || '').split('.');

    if (parts.length !== 2) {
      return null;
    }

    const [raw, sig] = parts;

    const secret =
      process.env.SESSION_SECRET ||
      'dev-only-secret';

    const expected =
      b64url(
        crypto
          .createHmac(
            'sha256',
            secret
          )
          .update(raw)
          .digest()
      );

    const receivedBuffer =
      Buffer.from(sig);

    const expectedBuffer =
      Buffer.from(expected);

    if (
      receivedBuffer.length !==
      expectedBuffer.length
    ) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        receivedBuffer,
        expectedBuffer
      )
    ) {
      return null;
    }

    const payload =
      JSON.parse(
        ub64url(raw).toString('utf8')
      );

    if (
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function setCookie(
  res,
  name,
  value,
  maxAge = 604800
) {
  const secure =
    process.env.NODE_ENV === 'production'
      ? '; Secure'
      : '';

  res.setHeader(
    'Set-Cookie',
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`
  );
}

function clearCookie(
  res,
  name
) {
  res.setHeader(
    'Set-Cookie',
    `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
}

function getCookie(
  req,
  name
) {
  const raw =
    req.headers.cookie || '';

  const item =
    raw
      .split(';')
      .map(x => x.trim())
      .find(
        x => x.startsWith(name + '=')
      );

  if (!item) {
    return '';
  }

  return decodeURIComponent(
    item.slice(name.length + 1)
  );
}

async function getSessionUser(req) {
  const token =
    verify(
      getCookie(
        req,
        'doktoruz_session'
      )
    );

  if (!token?.uid) {
    return null;
  }

  const result =
    await query(
      `
      SELECT
        id,
        phone,
        name,
        role,
        phone_verified,
        created_at,
        updated_at
      FROM users
      WHERE id = $1
      `,
      [token.uid]
    );

  return result.rows[0] || null;
}

async function requireUser(
  req,
  res
) {
  const user =
    await getSessionUser(req);

  if (!user) {
    res.statusCode = 401;
    throw new Error(
      'Требуется вход'
    );
  }

  return user;
}

async function requireAdmin(
  req,
  res
) {
  const user =
    await requireUser(
      req,
      res
    );

  if (
    ![
      'admin',
      'master_admin'
    ].includes(
      user.role
    )
  ) {
    res.statusCode = 403;

    throw new Error(
      'Недостаточно прав'
    );
  }

  return user;
}

async function requireMaster(
  req,
  res
) {
  const user =
    await requireUser(
      req,
      res
    );

  if (
    user.role !==
    'master_admin'
  ) {
    res.statusCode = 403;

    throw new Error(
      'Только главный администратор'
    );
  }

  return user;
}

function hashOtp(code) {
  const secret =
    process.env.SESSION_SECRET ||
    'otp';

  return crypto
    .createHash('sha256')
    .update(
      String(code) +
      '|' +
      secret
    )
    .digest('hex');
}

function generateOtp() {
  return String(
    Math.floor(
      100000 +
      Math.random() * 900000
    )
  );
}

function verifyPassword(input) {
  const spec =
    String(
      process.env.ADMIN_PASSWORD_HASH ||
      ''
    );

  if (
    spec.startsWith('scrypt$')
  ) {
    try {
      const [
        ,
        n,
        r,
        p,
        saltB64,
        hashB64
      ] = spec.split('$');

      const salt =
        Buffer.from(
          saltB64
            .replace(/-/g, '+')
            .replace(/_/g, '/'),
          'base64'
        );

      const expected =
        Buffer.from(
          hashB64
            .replace(/-/g, '+')
            .replace(/_/g, '/'),
          'base64'
        );

      const actual =
        crypto.scryptSync(
          String(input),
          salt,
          expected.length,
          {
            N: Number(n),
            r: Number(r),
            p: Number(p)
          }
        );

      return crypto.timingSafeEqual(
        actual,
        expected
      );
    } catch {
      return false;
    }
  }

  return (
    !!spec &&
    String(input) === spec
  );
}

module.exports = {
  normalizePhone,
  e164,
  sign,
  verify,
  setCookie,
  clearCookie,
  getCookie,
  getSessionUser,
  requireUser,
  requireAdmin,
  requireMaster,
  hashOtp,
  generateOtp,
  verifyPassword
};
