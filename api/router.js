const fs = require('fs');
const path = require('path');

const {
  query
} = require('./_lib/db');

const {
  normalizePhone,
  e164,
  sign,
  setCookie,
  clearCookie,
  getSessionUser,
  requireUser,
  requireAdmin,
  requireMaster,
  hashOtp,
  generateOtp,
  verifyPassword
} = require('./_lib/auth');

async function body(req) {
  if (req.body && typeof req.body === 'object') {
    return req.body;
  }

  return new Promise((resolve, reject) => {
    let raw = '';

    req.on('data', chunk => {
      raw += chunk;

      if (raw.length > 5e6) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });

    req.on('error', reject);
  });
}

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader(
    'Content-Type',
    'application/json; charset=utf-8'
  );

  res.end(JSON.stringify(data));
}

function ok(res, data) {
  json(res, 200, {
    ok: true,
    ...data
  });
}

function bad(res, status, message) {
  json(res, status, {
    ok: false,
    error: message
  });
}

async function log(actor, action, details) {
  try {
    await query(
      `
      INSERT INTO admin_logs(actor_id, action, details)
      VALUES($1, $2, $3)
      `,
      [
        actor?.id || null,
        action,
        details || null
      ]
    );
  } catch (error) {
    console.error('Admin log error:', error);
  }
}

function route(req) {
  return new URL(
    req.url,
    'http://local'
  ).searchParams.get('action') || '';
}


/* =========================================================
   TWILIO SMS
========================================================= */

async function sendTwilioOtp(phone) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const service = process.env.TWILIO_VERIFY_SERVICE_SID;

  if (!sid || !token || !service) {
    throw new Error(
      'Twilio SMS is not configured'
    );
  }

  const auth = Buffer
    .from(`${sid}:${token}`)
    .toString('base64');

  const form = new URLSearchParams({
    To: e164(phone),
    Channel: 'sms'
  });

  const response = await fetch(
    `https://verify.twilio.com/v2/Services/${encodeURIComponent(
      service
    )}/Verifications`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body: form
    }
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Twilio: ${text.slice(0, 300)}`
    );
  }
}

async function verifyTwilioOtp(phone, code) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const service = process.env.TWILIO_VERIFY_SERVICE_SID;

  if (!sid || !token || !service) {
    return false;
  }

  const auth = Buffer
    .from(`${sid}:${token}`)
    .toString('base64');

  const form = new URLSearchParams({
    To: e164(phone),
    Code: String(code)
  });

  const response = await fetch(
    `https://verify.twilio.com/v2/Services/${encodeURIComponent(
      service
    )}/VerificationCheck`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body: form
    }
  );

  let data = {};

  try {
    data = await response.json();
  } catch (error) {
    return false;
  }

  return response.ok &&
    data.status === 'approved';
}


/* =========================================================
   DATABASE SETUP
========================================================= */

async function setup(req, res) {
  if (
    process.env.SETUP_ENABLED !== 'true' ||
    !process.env.SETUP_TOKEN
  ) {
    return bad(
      res,
      404,
      'Setup disabled'
    );
  }

  const token =
    req.headers['x-setup-token'] ||
    new URL(
      req.url,
      'http://local'
    ).searchParams.get('token');

  if (token !== process.env.SETUP_TOKEN) {
    return bad(
      res,
      403,
      'Invalid setup token'
    );
  }

  const sql = fs.readFileSync(
    path.join(
      process.cwd(),
      'schema.sql'
    ),
    'utf8'
  );

  await query(sql);

  return ok(res, {
    message:
      'Database schema is ready'
  });
}


/* =========================================================
   AUTH START
========================================================= */

async function authStart(req, res) {
  const data = await body(req);

  const phone =
    normalizePhone(data.phone);

  const purpose =
    data.purpose === 'login'
      ? 'login'
      : 'register';

  const name =
    String(data.name || '').trim();

  if (!/^998\d{9}$/.test(phone)) {
    return bad(
      res,
      400,
      'Введите корректный номер телефона'
    );
  }

  if (
    purpose === 'register' &&
    name.length < 2
  ) {
    return bad(
      res,
      400,
      'Введите имя'
    );
  }

  const masterPhone =
    normalizePhone(
      process.env.MASTER_ADMIN_PHONE ||
      '998933763262'
    );

  if (
    purpose === 'register' &&
    phone === masterPhone
  ) {
    if (
      !verifyPassword(
        data.adminPassword || ''
      )
    ) {
      return bad(
        res,
        403,
        'Для главного администратора нужен правильный пароль'
      );
    }
  }

  const existing = await query(
    `
    SELECT id, name, role
    FROM users
    WHERE phone = $1
    `,
    [phone]
  );

  if (
    purpose === 'login' &&
    !existing.rows[0]
  ) {
    return bad(
      res,
      404,
      'Пользователь с таким номером не найден'
    );
  }

  await query(
    `
    DELETE FROM otp_codes
    WHERE phone = $1
       OR expires_at < now()
    `,
    [phone]
  );

  const mode =
    process.env.SMS_MODE || 'demo';

  let demoOtp = null;

  if (mode === 'twilio') {
    await sendTwilioOtp(phone);
  } else {
    demoOtp = generateOtp();

    await query(
      `
      INSERT INTO otp_codes(
        phone,
        purpose,
        code_hash,
        expires_at
      )
      VALUES(
        $1,
        $2,
        $3,
        now() + interval '5 minutes'
      )
      `,
      [
        phone,
        purpose,
        hashOtp(demoOtp)
      ]
    );
  }

  return ok(res, {
    phone,
    purpose,
    ...(demoOtp
      ? { demoOtp }
      : {})
  });
}


/* =========================================================
   AUTH VERIFY
========================================================= */

async function authVerify(req, res) {
  const data = await body(req);

  const phone =
    normalizePhone(data.phone);

  const purpose =
    data.purpose === 'login'
      ? 'login'
      : 'register';

  const code =
    String(data.code || '').trim();

  const mode =
    process.env.SMS_MODE || 'demo';

  if (
    !/^998\d{9}$/.test(phone) ||
    !/^\d{6}$/.test(code)
  ) {
    return bad(
      res,
      400,
      'Неверный номер или код'
    );
  }

  let valid = false;

  if (mode === 'twilio') {
    valid =
      await verifyTwilioOtp(
        phone,
        code
      );
  } else {
    const result = await query(
      `
      SELECT
        id,
        code_hash,
        attempts
      FROM otp_codes
      WHERE phone = $1
        AND purpose = $2
        AND expires_at > now()
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [
        phone,
        purpose
      ]
    );

    const row =
      result.rows[0];

    if (row) {
      if (row.attempts >= 5) {
        return bad(
          res,
          429,
          'Слишком много попыток. Запросите новый код.'
        );
      }

      valid =
        hashOtp(code) ===
        row.code_hash;

      await query(
        `
        UPDATE otp_codes
        SET attempts = attempts + 1
        WHERE id = $1
        `,
        [row.id]
      );
    }
  }

  if (!valid) {
    return bad(
      res,
      400,
      'Неверный SMS-код'
    );
  }

  let user;

  const existing =
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
      WHERE phone = $1
      `,
      [phone]
    );

  const master =
    phone === normalizePhone(
      process.env.MASTER_ADMIN_PHONE ||
      '998933763262'
    );

  if (existing.rows[0]) {
    const current =
      existing.rows[0];

    const updated =
      await query(
        `
        UPDATE users
        SET
          phone_verified = true,
          updated_at = now(),
          name =
            CASE
              WHEN $2 <> ''
               AND $2 IS NOT NULL
              THEN $2
              ELSE name
            END,
          role =
            CASE
              WHEN $3
              THEN 'master_admin'
              ELSE role
            END
        WHERE id = $1
        RETURNING
          id,
          phone,
          name,
          role,
          phone_verified,
          created_at,
          updated_at
        `,
        [
          current.id,
          String(data.name || ''),
          master
        ]
      );

    user =
      updated.rows[0];
  } else {
    const inserted =
      await query(
        `
        INSERT INTO users(
          phone,
          name,
          role,
          phone_verified
        )
        VALUES(
          $1,
          $2,
          $3,
          true
        )
        RETURNING
          id,
          phone,
          name,
          role,
          phone_verified,
          created_at,
          updated_at
        `,
        [
          phone,
          String(
            data.name ||
            'Пользователь'
          ),
          master
            ? 'master_admin'
            : 'user'
        ]
      );

    user =
      inserted.rows[0];
  }

  await query(
    `
    DELETE FROM otp_codes
    WHERE phone = $1
      AND purpose = $2
    `,
    [
      phone,
      purpose
    ]
  );

  const token =
    sign({
      uid: user.id,
      exp:
        Date.now() +
        7 * 24 * 60 * 60 * 1000
    });

  setCookie(
    res,
    'doktoruz_session',
    token
  );

  return ok(res, {
    user
  });
}


/* =========================================================
   BOOTSTRAP
========================================================= */

async function bootstrap(req, res) {
  const user =
    await getSessionUser(req);

  const doctors =
    await query(
      `
      SELECT
        id,
        name,
        phone,
        specialty,
        experience,
        rating,
        price,
        status,
        clinic_name,
        description,
        created_at
      FROM doctors
      WHERE status = 'active'
      ORDER BY created_at DESC
      `
    );

  const ads =
    await query(
      `
      SELECT
        id,
        title,
        body,
        media_type,
        media_url,
        show_home,
        created_at
      FROM ads
      WHERE show_home = true
      ORDER BY created_at DESC
      `
    );

  return ok(res, {
    user,
    doctors:
      doctors.rows,
    ads:
      ads.rows
  });
}


/* =========================================================
   DOCTORS
========================================================= */

async function findOrCreateDoctor({
  doctorId,
  name,
  specialty,
  phone,
  clinicName
}) {
  if (doctorId) {
    const result =
      await query(
        `
        SELECT *
        FROM doctors
        WHERE id = $1
        `,
        [doctorId]
      );

    if (result.rows[0]) {
      return result.rows[0];
    }
  }

  const existing =
    await query(
      `
      SELECT *
      FROM doctors
      WHERE name = $1
        AND COALESCE(phone, '') =
            COALESCE($2, '')
        AND status <> 'deleted'
      LIMIT 1
      `,
      [
        name,
        phone || null
      ]
    );

  if (existing.rows[0]) {
    return existing.rows[0];
  }

  const inserted =
    await query(
      `
      INSERT INTO doctors(
        name,
        phone,
        specialty,
        clinic_name,
        status
      )
      VALUES(
        $1,
        $2,
        $3,
        $4,
        'active'
      )
      RETURNING *
      `,
      [
        name,
        phone || null,
        specialty || 'Врач',
        clinicName || '—'
      ]
    );

  return inserted.rows[0];
}


/* =========================================================
   AVAILABILITY
========================================================= */

async function availability(req, res) {
  const url =
    new URL(
      req.url,
      'http://local'
    );

  const doctorId =
    url.searchParams.get(
      'doctor_id'
    );

  const doctorName =
    url.searchParams.get(
      'doctor_name'
    ) || '';

  const date =
    url.searchParams.get(
      'date'
    );

  if (!date) {
    return bad(
      res,
      400,
      'Не хватает даты'
    );
  }

  let result;

  if (doctorId) {
    result =
      await query(
        `
        SELECT
          appointment_time::text AS time
        FROM appointments
        WHERE doctor_id = $1
          AND appointment_date = $2
          AND status <> 'cancelled'
        `,
        [
          doctorId,
          date
        ]
      );
  } else {
    result =
      await query(
        `
        SELECT
          appointment_time::text AS time
        FROM appointments
        WHERE doctor_name = $1
          AND appointment_date = $2
          AND status <> 'cancelled'
        `,
        [
          doctorName,
          date
        ]
      );
  }

  return ok(res, {
    taken:
      result.rows.map(
        row =>
          String(
            row.time
          ).slice(0, 5)
      )
  });
}


/* =========================================================
   APPOINTMENTS
========================================================= */

async function createAppointment(req, res) {
  const user =
    await requireUser(
      req,
      res
    );

  const data =
    await body(req);

  const doctor =
    await findOrCreateDoctor({
      doctorId:
        data.doctorId,
      name:
        data.doctorName,
      specialty:
        data.doctorSpecialty,
      phone:
        data.doctorPhone,
      clinicName:
        data.clinicName
    });

  if (
    doctor.status !== 'active'
  ) {
    return bad(
      res,
      409,
      'Этот врач недоступен для записи'
    );
  }

  try {
    const inserted =
      await query(
        `
        INSERT INTO appointments(
          patient_id,
          patient_name,
          patient_phone,
          doctor_id,
          doctor_name,
          doctor_specialty,
          clinic_name,
          appointment_date,
          appointment_time,
          payment,
          status
        )
        VALUES(
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10,
          'confirmed'
        )
        RETURNING *
        `,
        [
          user.id,
          user.name,
          user.phone,
          doctor.id,
          doctor.name,
          doctor.specialty,
          doctor.clinic_name || '—',
          data.date,
          data.time,
          data.payment || 'Наличные'
        ]
      );

    return ok(res, {
      appointment:
        inserted.rows[0]
    });
  } catch (error) {
    if (error.code === '23505') {
      return bad(
        res,
        409,
        'Это время уже занято. Выберите другое.'
      );
    }

    throw error;
  }
}

async function userAppointments(req, res) {
  const user =
    await requireUser(
      req,
      res
    );

  const result =
    await query(
      `
      SELECT *
      FROM appointments
      WHERE patient_id = $1
         OR patient_phone = $2
      ORDER BY
        appointment_date DESC,
        appointment_time DESC
      `,
      [
        user.id,
        user.phone
      ]
    );

  return ok(res, {
    appointments:
      result.rows
  });
}

async function cancelMy(req, res) {
  const user =
    await requireUser(
      req,
      res
    );

  const data =
    await body(req);

  const result =
    await query(
      `
      UPDATE appointments
      SET
        status = 'cancelled',
        cancelled_at = now(),
        cancelled_by = $3
      WHERE id = $1
        AND (
          patient_id = $2
          OR patient_phone = $4
        )
        AND status = 'confirmed'
      RETURNING *
      `,
      [
        data.id,
        user.id,
        user.id,
        user.phone
      ]
    );

  if (!result.rows[0]) {
    return bad(
      res,
      404,
      'Запись не найдена'
    );
  }

  return ok(res, {
    appointment:
      result.rows[0]
  });
}


/* =========================================================
   DOCTOR APPLICATION
========================================================= */

async function submitApplication(req, res) {
  const user =
    await requireUser(
      req,
      res
    );

  const data =
    await body(req);

  const specialty =
    String(
      data.specialty || ''
    ).trim();

  const experience =
    String(
      data.experience || ''
    ).trim();

  const description =
    String(
      data.description || ''
    ).trim();

  const phone =
    normalizePhone(
      data.phone ||
      user.phone
    );

  if (
    specialty.length < 3 ||
    !/^\d{1,2}$/.test(
      experience
    ) ||
    description.length < 10
  ) {
    return bad(
      res,
      400,
      'Проверьте данные заявки'
    );
  }

  const duplicate =
    await query(
      `
      SELECT id
      FROM doctor_applications
      WHERE phone = $1
        AND status = 'pending'
      LIMIT 1
      `,
      [phone]
    );

  if (duplicate.rows[0]) {
    return bad(
      res,
      409,
      'Заявка с этим номером уже находится на модерации'
    );
  }

  const result =
    await query(
      `
      INSERT INTO doctor_applications(
        user_id,
        name,
        phone,
        specialty,
        experience,
        description,
        verification
      )
      VALUES(
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7
      )
      RETURNING *
      `,
      [
        user.id,
        user.name,
        phone,
        specialty,
        experience,
        description,
        data.verification || 'submitted'
      ]
    );

  return ok(res, {
    application:
      result.rows[0]
  });
}


/* =========================================================
   ADMIN USERS
========================================================= */

async function adminUsers(req, res) {
  await requireAdmin(
    req,
    res
  );

  const queryText =
    new URL(
      req.url,
      'http://local'
    ).searchParams.get('q') || '';

  const result =
    await query(
      `
      SELECT
        id,
        name,
        phone,
        role,
        phone_verified,
        created_at,
        updated_at
      FROM users
      WHERE
        name ILIKE $1
        OR phone ILIKE $1
      ORDER BY created_at DESC
      `,
      ['%' + queryText + '%']
    );

  return ok(res, {
    users:
      result.rows
  });
}

async function adminDeleteUser(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  const result =
    await query(
      `
      SELECT *
      FROM users
      WHERE id = $1
      `,
      [data.id]
    );

  const user =
    result.rows[0];

  if (!user) {
    return bad(
      res,
      404,
      'Пользователь не найден'
    );
  }

  if (
    user.role === 'master_admin'
  ) {
    return bad(
      res,
      403,
      'Нельзя удалить главного администратора'
    );
  }

  await query(
    `
    DELETE FROM users
    WHERE id = $1
    `,
    [user.id]
  );

  await log(
    admin,
    'Удалён пользователь',
    user.phone
  );

  return ok(res, {});
}


/* =========================================================
   ADMIN APPOINTMENTS
========================================================= */

async function adminAppointments(req, res) {
  await requireAdmin(
    req,
    res
  );

  const queryText =
    new URL(
      req.url,
      'http://local'
    ).searchParams.get('q') || '';

  const result =
    await query(
      `
      SELECT *
      FROM appointments
      WHERE
        patient_name ILIKE $1
        OR patient_phone ILIKE $1
        OR doctor_name ILIKE $1
      ORDER BY
        appointment_date DESC,
        appointment_time DESC
      `,
      ['%' + queryText + '%']
    );

  return ok(res, {
    appointments:
      result.rows
  });
}

async function adminAppointmentAction(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  if (
    ![
      'cancelled',
      'completed'
    ].includes(
      data.status
    )
  ) {
    return bad(
      res,
      400,
      'Недопустимый статус'
    );
  }

  const result =
    await query(
      `
      UPDATE appointments
      SET
        status = $2,

        cancelled_at =
          CASE
            WHEN $2 = 'cancelled'
            THEN now()
            ELSE cancelled_at
          END,

        cancelled_by =
          CASE
            WHEN $2 = 'cancelled'
            THEN $3
            ELSE cancelled_by
          END,

        completed_at =
          CASE
            WHEN $2 = 'completed'
            THEN now()
            ELSE completed_at
          END

      WHERE id = $1
      RETURNING *
      `,
      [
        data.id,
        data.status,
        admin.id
      ]
    );

  if (!result.rows[0]) {
    return bad(
      res,
      404,
      'Запись не найдена'
    );
  }

  await log(
    admin,
    data.status === 'cancelled'
      ? 'Отменена запись'
      : 'Завершена запись',
    `${result.rows[0].patient_name} → ${result.rows[0].doctor_name}`
  );

  return ok(res, {
    appointment:
      result.rows[0]
  });
}

async function adminDeleteAppointment(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  const result =
    await query(
      `
      DELETE FROM appointments
      WHERE id = $1
      RETURNING *
      `,
      [data.id]
    );

  if (!result.rows[0]) {
    return bad(
      res,
      404,
      'Запись не найдена'
    );
  }

  await log(
    admin,
    'Удалена запись из истории',
    String(
      result.rows[0].id
    )
  );

  return ok(res, {});
}


/* =========================================================
   ADMIN DOCTORS
========================================================= */

async function adminDoctors(req, res) {
  await requireAdmin(
    req,
    res
  );

  const queryText =
    new URL(
      req.url,
      'http://local'
    ).searchParams.get('q') || '';

  const result =
    await query(
      `
      SELECT *
      FROM doctors
      WHERE status <> 'deleted'
        AND (
          name ILIKE $1
          OR COALESCE(phone, '') ILIKE $1
        )
      ORDER BY created_at DESC
      `,
      ['%' + queryText + '%']
    );

  return ok(res, {
    doctors:
      result.rows
  });
}

async function adminDoctorAction(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  if (
    data.action === 'delete'
  ) {
    const result =
      await query(
        `
        UPDATE doctors
        SET
          status = 'deleted',
          updated_at = now()
        WHERE id = $1
        RETURNING *
        `,
        [data.id]
      );

    if (!result.rows[0]) {
      return bad(
        res,
        404,
        'Врач не найден'
      );
    }

    await log(
      admin,
      'Удалён врач',
      result.rows[0].name
    );

    return ok(res, {
      doctor:
        result.rows[0]
    });
  }

  if (
    data.action === 'toggle_block'
  ) {
    const result =
      await query(
        `
        UPDATE doctors
        SET
          status =
            CASE
              WHEN status = 'blocked'
              THEN 'active'
              ELSE 'blocked'
            END,
          updated_at = now()
        WHERE id = $1
        RETURNING *
        `,
        [data.id]
      );

    if (!result.rows[0]) {
      return bad(
        res,
        404,
        'Врач не найден'
      );
    }

    await log(
      admin,
      result.rows[0].status === 'blocked'
        ? 'Заблокирован врач'
        : 'Разблокирован врач',
      result.rows[0].name
    );

    return ok(res, {
      doctor:
        result.rows[0]
    });
  }

  return bad(
    res,
    400,
    'Недопустимое действие'
  );
}


/* =========================================================
   ADMIN APPLICATIONS
========================================================= */

async function adminApplications(req, res) {
  await requireAdmin(
    req,
    res
  );

  const result =
    await query(
      `
      SELECT *
      FROM doctor_applications
      WHERE status = 'pending'
      ORDER BY submitted_at ASC
      `
    );

  return ok(res, {
    applications:
      result.rows
  });
}

async function adminApplicationAction(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  const applicationResult =
    await query(
      `
      SELECT *
      FROM doctor_applications
      WHERE id = $1
      `,
      [data.id]
    );

  const application =
    applicationResult.rows[0];

  if (!application) {
    return bad(
      res,
      404,
      'Заявка не найдена'
    );
  }

  if (
    application.status !== 'pending'
  ) {
    return bad(
      res,
      409,
      'Заявка уже обработана'
    );
  }

  /* ---- reject ---- */

  if (
    data.action === 'reject'
  ) {
    const updated =
      await query(
        `
        UPDATE doctor_applications
        SET
          status = 'rejected',
          rejection_reason = $2,
          decided_at = now(),
          decided_by = $3
        WHERE id = $1
        RETURNING *
        `,
        [
          data.id,
          String(
            data.reason || ''
          ),
          admin.id
        ]
      );

    await log(
      admin,
      'Отклонена заявка врача',
      `${application.name} · ${
        data.reason || 'без причины'
      }`
    );

    return ok(res, {
      application:
        updated.rows[0]
    });
  }

  /* ---- approve ---- */

  if (
    data.action === 'approve'
  ) {
    const doctor =
      await query(
        `
        INSERT INTO doctors(
          name,
          phone,
          specialty,
          experience,
          description,
          status,
          source_application_id
        )
        VALUES(
          $1,
          $2,
          $3,
          $4,
          $5,
          'active',
          $6
        )
        ON CONFLICT (
          name,
          COALESCE(phone, '')
        )
        DO UPDATE
        SET
          status = 'active',
          specialty =
            excluded.specialty,
          experience =
            excluded.experience,
          description =
            excluded.description,
          source_application_id =
            excluded.source_application_id
        RETURNING *
        `,
        [
          application.name,
          application.phone,
          application.specialty,
          application.experience,
          application.description,
          application.id
        ]
      );

    const updated =
      await query(
        `
        UPDATE doctor_applications
        SET
          status = 'approved',
          decided_at = now(),
          decided_by = $2
        WHERE id = $1
        RETURNING *
        `,
        [
          data.id,
          admin.id
        ]
      );

    await log(
      admin,
      'Одобрена заявка врача',
      `${application.name} · ${application.specialty}`
    );

    return ok(res, {
      application:
        updated.rows[0],
      doctor:
        doctor.rows[0]
    });
  }

  return bad(
    res,
    400,
    'Недопустимое действие'
  );
}


/* =========================================================
   ADMIN ADS
========================================================= */

async function adminAds(req, res) {
  await requireAdmin(
    req,
    res
  );

  const result =
    await query(
      `
      SELECT *
      FROM ads
      ORDER BY created_at DESC
      `
    );

  return ok(res, {
    ads:
      result.rows
  });
}

async function adminCreateAd(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  if (
    !data.title ||
    !data.mediaUrl ||
    ![
      'image',
      'video'
    ].includes(
      data.mediaType
    )
  ) {
    return bad(
      res,
      400,
      'Заполните заголовок и медиа'
    );
  }

  const result =
    await query(
      `
      INSERT INTO ads(
        title,
        body,
        media_type,
        media_url,
        show_home,
        created_by
      )
      VALUES(
        $1,
        $2,
        $3,
        $4,
        $5,
        $6
      )
      RETURNING *
      `,
      [
        String(
          data.title
        ).trim(),

        String(
          data.body || ''
        ).trim(),

        data.mediaType,

        data.mediaUrl,

        data.showHome !== false,

        admin.id
      ]
    );

  await log(
    admin,
    'Опубликована реклама',
    data.title
  );

  return ok(res, {
    ad:
      result.rows[0]
  });
}

async function adminAdAction(req, res) {
  const admin =
    await requireAdmin(
      req,
      res
    );

  const data =
    await body(req);

  if (
    data.action === 'delete'
  ) {
    const result =
      await query(
        `
        DELETE FROM ads
        WHERE id = $1
        RETURNING *
        `,
        [data.id]
      );

    if (!result.rows[0]) {
      return bad(
        res,
        404,
        'Реклама не найдена'
      );
    }

    await log(
      admin,
      'Удалена реклама',
      result.rows[0].title
    );

    return ok(res, {});
  }

  if (
    data.action === 'toggle'
  ) {
    const result =
      await query(
        `
        UPDATE ads
        SET
          show_home = NOT show_home
        WHERE id = $1
        RETURNING *
        `,
        [data.id]
      );

    if (!result.rows[0]) {
      return bad(
        res,
        404,
        'Реклама не найдена'
      );
    }

    await log(
      admin,
      result.rows[0].show_home
        ? 'Показана реклама на главной'
        : 'Скрыта реклама с главной',
      result.rows[0].title
    );

    return ok(res, {
      ad:
        result.rows[0]
    });
  }

  return bad(
    res,
    400,
    'Недопустимое действие'
  );
}


/* =========================================================
   ADMIN ACCESS
========================================================= */

async function adminAccess(req, res) {
  const admin =
    await requireMaster(
      req,
      res
    );

  const data =
    await body(req);

  const phone =
    normalizePhone(
      data.phone
    );

  if (
    !/^998\d{9}$/.test(phone)
  ) {
    return bad(
      res,
      400,
      'Неверный номер'
    );
  }

  const masterPhone =
    normalizePhone(
      process.env.MASTER_ADMIN_PHONE ||
      '998933763262'
    );

  if (
    phone === masterPhone
  ) {
    return bad(
      res,
      400,
      'Это главный администратор'
    );
  }

  const result =
    await query(
      `
      UPDATE users
      SET
        role = 'admin',
        updated_at = now()
      WHERE phone = $1
      RETURNING
        id,
        name,
        phone,
        role
      `,
      [phone]
    );

  if (!result.rows[0]) {
    return bad(
      res,
      404,
      'Пользователь с таким номером ещё не зарегистрирован'
    );
  }

  await log(
    admin,
    'Выдан админ-доступ',
    phone
  );

  return ok(res, {
    user:
      result.rows[0]
  });
}

async function adminRevoke(req, res) {
  const admin =
    await requireMaster(
      req,
      res
    );

  const data =
    await body(req);

  const result =
    await query(
      `
      UPDATE users
      SET
        role = 'user',
        updated_at = now()
      WHERE id = $1
        AND role = 'admin'
      RETURNING
        id,
        name,
        phone,
        role
      `,
      [data.id]
    );

  if (!result.rows[0]) {
    return bad(
      res,
      404,
      'Администратор не найден'
    );
  }

  await log(
    admin,
    'Отозван админ-доступ',
    result.rows[0].phone
  );

  return ok(res, {
    user:
      result.rows[0]
  });
}


/* =========================================================
   ADMIN LOGS
========================================================= */

async function adminLogs(req, res) {
  await requireAdmin(
    req,
    res
  );

  const result =
    await query(
      `
      SELECT
        l.id,
        l.action,
        l.details,
        l.created_at,
        u.phone AS actor_phone,
        u.name AS actor_name
      FROM admin_logs l
      LEFT JOIN users u
        ON u.id = l.actor_id
      ORDER BY
        l.created_at DESC
      LIMIT 300
      `
    );

  return ok(res, {
    logs:
      result.rows
  });
}


/* =========================================================
   SYNC DOCTORS
========================================================= */

async function syncDoctors(req, res) {
  const admin =
    await requireMaster(
      req,
      res
    );

  const data =
    await body(req);

  const list =
    Array.isArray(data.doctors)
      ? data.doctors
      : [];

  for (const doctor of list) {
    if (!doctor?.n) {
      continue;
    }

    await query(
      `
      INSERT INTO doctors(
        name,
        phone,
        specialty,
        experience,
        rating,
        price,
        clinic_name,
        status
      )
      VALUES(
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        'active'
      )
      ON CONFLICT (
        name,
        COALESCE(phone, '')
      )
      DO UPDATE
      SET
        specialty =
          excluded.specialty,
        experience =
          excluded.experience,
        rating =
          excluded.rating,
        price =
          excluded.price,
        clinic_name =
          excluded.clinic_name,
        status =
          CASE
            WHEN doctors.status = 'blocked'
            THEN 'blocked'
            ELSE 'active'
          END
      `,
      [
        doctor.n,
        doctor.phone || null,
        doctor.s || 'Врач',
        doctor.e || '',
        doctor.r || 'Новый',
        doctor.p || 'Уточнить',
        doctor.clinicName || '—'
      ]
    );
  }

  await log(
    admin,
    'Синхронизирован каталог врачей',
    'demo/static → database'
  );

  return ok(res, {
    count:
      list.length
  });
}


/* =========================================================
   MAIN ROUTER
========================================================= */

async function main(req, res) {
  const action =
    route(req);

  if (action === 'setup') {
    return setup(req, res);
  }

  if (action === 'auth/start') {
    return authStart(
      req,
      res
    );
  }

  if (action === 'auth/verify') {
    return authVerify(
      req,
      res
    );
  }

  if (action === 'auth/me') {
    const user =
      await getSessionUser(
        req
      );

    return ok(res, {
      user
    });
  }

  if (action === 'auth/logout') {
    clearCookie(
      res,
      'doktoruz_session'
    );

    clearCookie(
      res,
      'doktoruz_admin'
    );

    return ok(res, {});
  }

  if (action === 'bootstrap') {
    return bootstrap(
      req,
      res
    );
  }

  if (
    action ===
    'appointments/availability'
  ) {
    return availability(
      req,
      res
    );
  }

  if (
    action ===
    'appointments/create'
  ) {
    return createAppointment(
      req,
      res
    );
  }

  if (
    action ===
    'appointments/mine'
  ) {
    return userAppointments(
      req,
      res
    );
  }

  if (
    action ===
    'appointments/cancel'
  ) {
    return cancelMy(
      req,
      res
    );
  }

  if (
    action ===
    'doctor-applications/create'
  ) {
    return submitApplication(
      req,
      res
    );
  }

  if (
    action ===
    'admin/verify'
  ) {
    const user =
      await requireUser(
        req,
        res
      );

    const data =
      await body(req);

    if (
      ![
        'admin',
        'master_admin'
      ].includes(
        user.role
      )
    ) {
      return bad(
        res,
        403,
        'Недостаточно прав'
      );
    }

    if (
      !verifyPassword(
        data.password || ''
      )
    ) {
      return bad(
        res,
        401,
        'Неверный код администратора'
      );
    }

    const token =
      sign({
        uid: user.id,
        admin: true,
        exp:
          Date.now() +
          60 * 60 * 1000
      });

    setCookie(
      res,
      'doktoruz_admin',
      token,
      3600
    );

    return ok(res, {
      role:
        user.role
    });
  }

  if (
    action ===
    'admin/users'
  ) {
    return adminUsers(
      req,
      res
    );
  }

  if (
    action ===
    'admin/users/delete'
  ) {
    return adminDeleteUser(
      req,
      res
    );
  }

  if (
    action ===
    'admin/appointments'
  ) {
    return adminAppointments(
      req,
      res
    );
  }

  if (
    action ===
    'admin/appointments/action'
  ) {
    return adminAppointmentAction(
      req,
      res
    );
  }

  if (
    action ===
    'admin/appointments/delete'
  ) {
    return adminDeleteAppointment(
      req,
      res
    );
  }

  if (
    action ===
    'admin/doctors'
  ) {
    return adminDoctors(
      req,
      res
    );
  }

  if (
    action ===
    'admin/doctors/action'
  ) {
    return adminDoctorAction(
      req,
      res
    );
  }

  if (
    action ===
    'admin/applications'
  ) {
    return adminApplications(
      req,
      res
    );
  }

  if (
    action ===
    'admin/applications/action'
  ) {
    return adminApplicationAction(
      req,
      res
    );
  }

  if (
    action ===
    'admin/ads'
  ) {
    return adminAds(
      req,
      res
    );
  }

  if (
    action ===
    'admin/ads/create'
  ) {
    return adminCreateAd(
      req,
      res
    );
  }

  if (
    action ===
    'admin/ads/action'
  ) {
    return adminAdAction(
      req,
      res
    );
  }

  if (
    action ===
    'admin/access/grant'
  ) {
    return adminAccess(
      req,
      res
    );
  }

  if (
    action ===
    'admin/access/revoke'
  ) {
    return adminRevoke(
      req,
      res
    );
  }

  if (
    action ===
    'admin/logs'
  ) {
    return adminLogs(
      req,
      res
    );
  }

  if (
    action ===
    'admin/doctors/sync'
  ) {
    return syncDoctors(
      req,
      res
    );
  }

  return bad(
    res,
    404,
    'Unknown action'
  );
}


module.exports = async function handler(
  req,
  res
) {
  try {
    await main(
      req,
      res
    );
  } catch (error) {
    console.error(
      error
    );

    if (!res.headersSent) {
      return bad(
        res,
        res.statusCode >= 400
          ? res.statusCode
          : 500,
        error.message ||
          'Server error'
      );
    }
  }
};
