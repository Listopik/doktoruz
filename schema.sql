CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone text NOT NULL UNIQUE,
  name text NOT NULL,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin','master_admin')),
  phone_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id bigserial PRIMARY KEY,
  phone text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('register','login')),
  code_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS otp_codes_phone_purpose_idx ON otp_codes(phone,purpose,created_at DESC);

CREATE TABLE IF NOT EXISTS doctors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  phone text,
  specialty text NOT NULL,
  experience text,
  rating text DEFAULT 'Новый',
  price text DEFAULT 'Уточнить',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','deleted')),
  clinic_name text DEFAULT '—',
  description text,
  source_application_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS doctors_name_phone_uq ON doctors(name, COALESCE(phone,''));
CREATE INDEX IF NOT EXISTS doctors_name_idx ON doctors(lower(name));
CREATE INDEX IF NOT EXISTS doctors_phone_idx ON doctors(phone);

CREATE TABLE IF NOT EXISTS doctor_applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  name text NOT NULL,
  phone text NOT NULL,
  specialty text NOT NULL,
  experience text,
  description text,
  verification jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  rejection_reason text,
  submitted_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  decided_by uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS doctor_applications_status_idx ON doctor_applications(status,submitted_at DESC);

CREATE TABLE IF NOT EXISTS appointments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  patient_id uuid REFERENCES users(id) ON DELETE SET NULL,
  patient_name text NOT NULL,
  patient_phone text NOT NULL,
  doctor_id uuid REFERENCES doctors(id) ON DELETE SET NULL,
  doctor_name text NOT NULL,
  doctor_specialty text,
  clinic_name text,
  appointment_date date NOT NULL,
  appointment_time time NOT NULL,
  payment text,
  status text NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed','cancelled','completed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  cancelled_at timestamptz,
  cancelled_by uuid REFERENCES users(id) ON DELETE SET NULL,
  completed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS appointments_active_slot_uq
  ON appointments(doctor_id, appointment_date, appointment_time)
  WHERE status <> 'cancelled';
CREATE INDEX IF NOT EXISTS appointments_patient_idx ON appointments(patient_id,appointment_date DESC);
CREATE INDEX IF NOT EXISTS appointments_date_idx ON appointments(appointment_date,appointment_time);

CREATE TABLE IF NOT EXISTS ads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  body text,
  media_type text NOT NULL CHECK (media_type IN ('image','video')),
  media_url text NOT NULL,
  show_home boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clinics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  type_name text,
  rating text DEFAULT 'Новый',
  reviews_count text DEFAULT '0',
  distance text,
  gradient text,
  description text,
  address text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','deleted')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_logs (
  id bigserial PRIMARY KEY,
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  action text NOT NULL,
  details text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_logs_created_idx ON admin_logs(created_at DESC);
