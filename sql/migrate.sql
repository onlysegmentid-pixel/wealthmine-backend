
create extension if not exists "pgcrypto";

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  username text not null,
  password_hash text not null,
  balance numeric not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists transactions (
  id text primary key,
  user_id uuid not null references users(id) on delete cascade,
  kind text not null,
  amount numeric not null,
  status text not null,
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_tx_user_created on transactions(user_id, created_at desc);

-- Seed admin user (idempotent)
do $$
declare
  admin_email text := current_setting('app.admin_email', true);
  admin_username text := 'Admin';
  admin_password_hash text := current_setting('app.admin_password_hash', true);
begin
  if admin_email is not null and admin_password_hash is not null then
    insert into users(email, username, password_hash)
    values (admin_email, admin_username, admin_password_hash)
    on conflict (email) do nothing;
  end if;
end $$;
