-- ============================================================================
-- KHEDUT SETU — 010 V3 MASTER UPGRADE SQL
-- Features: Multi-photo, Edit/Sold Toggle, Daily APMC Yard Rates, Local
--           Transport Directory, Seller Reviews, Secure UPI Payment Ledger.
-- Safe & Idempotent: Can be re-run safely without deleting existing data.
-- ============================================================================

-- 1. ADD SECURE UPI FIELDS TO PROFILES
alter table public.profiles add column if not exists upi_id text;
alter table public.profiles add column if not exists allow_upi_payment boolean not null default false;

-- 2. ADD SOLD STATUS COLUMNS TO PRODUCTS (Never conflicts with status CHECK/ENUM)
alter table public.products add column if not exists is_sold boolean not null default false;
alter table public.products add column if not exists sold_at timestamptz;

-- 3. UPGRADE PROFILE SECURITY TRIGGER (Add UPI VPA format validation)
create or replace function public.ks_guard_profile_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text;
begin
  if new.upi_id is not null then
    new.upi_id := lower(btrim(regexp_replace(new.upi_id, '[<>[:space:]]', '', 'g')));
    if new.upi_id = '' then
      new.upi_id := null;
    elsif new.upi_id !~ '^[a-z0-9._-]{2,64}@[a-z0-9.-]{2,32}$' then
      raise exception 'Invalid UPI ID format (example: name@okhdfcbank).';
    end if;
  end if;

  if new.full_name is not null then
    new.full_name := left(btrim(regexp_replace(new.full_name, '[<>]', '', 'g')), 100);
  end if;
  if new.business_name is not null then
    new.business_name := left(btrim(regexp_replace(new.business_name, '[<>]', '', 'g')), 120);
  end if;
  if new.village_city is not null then
    new.village_city := left(btrim(regexp_replace(new.village_city, '[<>]', '', 'g')), 100);
  end if;
  if new.district is not null then
    new.district := left(btrim(regexp_replace(new.district, '[<>]', '', 'g')), 100);
  end if;

  if auth.uid() is null then
    return new;
  end if;

  select role into v_caller_role from public.profiles where id = auth.uid();

  if coalesce(v_caller_role, '') <> 'admin' then
    if new.role is distinct from old.role then
      if new.role not in ('buyer', 'seller') then
        raise exception 'Unauthorized role escalation blocked.';
      end if;
    end if;
    if new.is_verified is distinct from old.is_verified then
      new.is_verified := old.is_verified;
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_profile_security on public.profiles;
create trigger trg_ks_guard_profile_security
  before update on public.profiles
  for each row execute function public.ks_guard_profile_security();

-- 4. UPGRADE PRODUCT SECURITY TRIGGER (Allow Seller Edit + Sold Toggle, Keep Status Locked)
create or replace function public.ks_guard_product_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text;
  v_recent_count integer;
begin
  if new.expected_price is null or new.expected_price <= 0 or new.expected_price > 100000000 then
    raise exception 'Invalid price range.';
  end if;
  if new.available_quantity is null or new.available_quantity <= 0 or new.available_quantity > 10000000 then
    raise exception 'Invalid quantity range.';
  end if;

  new.title_gu := left(btrim(regexp_replace(coalesce(new.title_gu, ''), '[<>]', '', 'g')), 160);
  new.title_hi := left(btrim(regexp_replace(coalesce(new.title_hi, new.title_gu), '[<>]', '', 'g')), 160);
  new.title_en := left(btrim(regexp_replace(coalesce(new.title_en, new.title_gu), '[<>]', '', 'g')), 160);
  if new.description_gu is not null then
    new.description_gu := left(btrim(regexp_replace(new.description_gu, '[<>]', '', 'g')), 2000);
  end if;
  if new.description_en is not null then
    new.description_en := left(btrim(regexp_replace(new.description_en, '[<>]', '', 'g')), 2000);
  end if;
  new.village := left(btrim(regexp_replace(coalesce(new.village, ''), '[<>]', '', 'g')), 100);
  new.district := left(btrim(regexp_replace(coalesce(new.district, ''), '[<>]', '', 'g')), 100);

  if char_length(new.title_gu) < 2 then
    raise exception 'Product title is too short.';
  end if;

  if new.is_sold = true and new.sold_at is null then
    new.sold_at := now();
  elsif new.is_sold = false then
    new.sold_at := null;
  end if;

  if auth.uid() is null then
    return new;
  end if;

  select role into v_caller_role from public.profiles where id = auth.uid();

  if tg_op = 'INSERT' then
    new.seller_id := auth.uid();
    if coalesce(v_caller_role, '') <> 'admin' then
      new.status := 'pending';
      new.is_featured := false;
      select count(*) into v_recent_count from public.products
      where seller_id = auth.uid() and created_at > now() - interval '24 hours';
      if v_recent_count >= 15 then
        raise exception 'Daily listing limit reached (15/day).';
      end if;
    end if;
  elsif tg_op = 'UPDATE' then
    if coalesce(v_caller_role, '') <> 'admin' then
      if new.seller_id is distinct from old.seller_id then
        raise exception 'Cannot transfer product ownership.';
      end if;
      if new.status is distinct from old.status then
        raise exception 'Only admins can approve or change product status.';
      end if;
      new.is_featured := old.is_featured;
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_product_security on public.products;
create trigger trg_ks_guard_product_security
  before insert or update on public.products
  for each row execute function public.ks_guard_product_security();

-- 5. SECURE RPC TO FETCH SELLER UPI DETAILS ONLY FOR LOGGED-IN USERS ON APPROVED LISTINGS
create or replace function public.get_product_seller_payment_info(p_product_id uuid)
returns table (
  seller_name text,
  upi_id text,
  allow_upi_payment boolean
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Login required to view payment details.';
  end if;

  return query
  select
    coalesce(pr.full_name, 'KHEDUT SETU Seller') as seller_name,
    case when pr.allow_upi_payment and pr.upi_id is not null then pr.upi_id else null end as upi_id,
    coalesce(pr.allow_upi_payment, false) as allow_upi_payment
  from public.products p
  join public.profiles pr on pr.id = p.seller_id
  where p.id = p_product_id
    and p.status = 'approved'
    and p.deleted_at is null;
end;
$$;

grant execute on function public.get_product_seller_payment_info(uuid) to authenticated;

-- 6. DAILY APMC / MARKET YARD RATES TABLE
create table if not exists public.apmc_rates (
  id uuid primary key default gen_random_uuid(),
  yard_name text not null,
  district text not null,
  crop_name_gu text not null,
  crop_name_en text,
  min_price numeric(12,2) not null check (min_price >= 0),
  max_price numeric(12,2) not null check (max_price >= min_price),
  modal_price numeric(12,2) not null check (modal_price >= 0),
  unit text not null default '20 kg (મણ)',
  rate_date date not null default current_date,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_apmc_rates_date on public.apmc_rates(rate_date desc, district);
alter table public.apmc_rates enable row level security;

drop policy if exists "apmc_rates_select_all" on public.apmc_rates;
create policy "apmc_rates_select_all" on public.apmc_rates
  for select using (true);

drop policy if exists "apmc_rates_admin_write" on public.apmc_rates;
create policy "apmc_rates_admin_write" on public.apmc_rates
  for all to authenticated
  using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'))
  with check (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));

-- Seed initial reference APMC rates only if empty (Admin can edit/add daily from Admin Panel)
insert into public.apmc_rates (yard_name, district, crop_name_gu, crop_name_en, min_price, max_price, modal_price, unit, rate_date)
select * from (values
  ('ખંભાત APMC', 'આણંદ', 'ડાંગર (ગુજરાત-૧૭)', 'Paddy Gujarat-17', 420.00, 510.00, 470.00, '20 kg (મણ)', current_date),
  ('આણંદ APMC', 'આણંદ', 'ઘઉં (ટુકડા)', 'Wheat Tukda', 510.00, 590.00, 555.00, '20 kg (મણ)', current_date),
  ('આણંદ APMC', 'આણંદ', 'બાજરી', 'Bajra', 430.00, 520.00, 480.00, '20 kg (મણ)', current_date),
  ('ઊંઝા APMC', 'મહેસાણા', 'જીરું', 'Cumin', 4400.00, 5150.00, 4800.00, '20 kg (મણ)', current_date),
  ('રાજકોટ APMC', 'રાજકોટ', 'મગફળી (જીણી)', 'Groundnut', 1080.00, 1320.00, 1210.00, '20 kg (મણ)', current_date),
  ('ગોંડલ APMC', 'રાજકોટ', 'કપાસ (બી.ટી.)', 'Cotton BT', 1420.00, 1580.00, 1510.00, '20 kg (મણ)', current_date)
) as seed(yard_name, district, crop_name_gu, crop_name_en, min_price, max_price, modal_price, unit, rate_date)
where not exists (select 1 from public.apmc_rates limit 1);

-- 7. LOCAL TEMPO / TRACTOR TRANSPORT DIRECTORY TABLE
create table if not exists public.transport_providers (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references auth.users(id) on delete set null,
  driver_name text not null,
  vehicle_type text not null,
  capacity_text text,
  village text not null,
  district text not null,
  mobile_number text not null,
  rate_note text,
  is_available boolean not null default true,
  created_at timestamptz not null default now()
);

create index if not exists idx_transport_district on public.transport_providers(district, is_available);
alter table public.transport_providers enable row level security;

drop policy if exists "transport_select_all" on public.transport_providers;
create policy "transport_select_all" on public.transport_providers
  for select using (true);

drop policy if exists "transport_insert_auth" on public.transport_providers;
create policy "transport_insert_auth" on public.transport_providers
  for insert to authenticated
  with check (owner_id = auth.uid());

drop policy if exists "transport_delete_owner_or_admin" on public.transport_providers;
create policy "transport_delete_owner_or_admin" on public.transport_providers
  for delete to authenticated
  using (
    owner_id = auth.uid()
    or exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

create or replace function public.ks_guard_transport_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  new.driver_name := left(btrim(regexp_replace(coalesce(new.driver_name, ''), '[<>]', '', 'g')), 80);
  new.vehicle_type := left(btrim(regexp_replace(coalesce(new.vehicle_type, ''), '[<>]', '', 'g')), 60);
  new.capacity_text := left(btrim(regexp_replace(coalesce(new.capacity_text, ''), '[<>]', '', 'g')), 60);
  new.village := left(btrim(regexp_replace(coalesce(new.village, ''), '[<>]', '', 'g')), 80);
  new.district := left(btrim(regexp_replace(coalesce(new.district, ''), '[<>]', '', 'g')), 80);
  new.rate_note := left(btrim(regexp_replace(coalesce(new.rate_note, ''), '[<>]', '', 'g')), 120);
  new.mobile_number := regexp_replace(coalesce(new.mobile_number, ''), '[^0-9]', '', 'g');

  if char_length(new.driver_name) < 2 or char_length(new.mobile_number) < 10 then
    raise exception 'Invalid driver name or mobile number.';
  end if;

  if auth.uid() is not null then
    new.owner_id := auth.uid();
    select count(*) into v_count from public.transport_providers where owner_id = auth.uid();
    if v_count >= 5 then
      raise exception 'Maximum 5 vehicles allowed per account.';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_ks_guard_transport_security on public.transport_providers;
create trigger trg_ks_guard_transport_security
  before insert on public.transport_providers
  for each row execute function public.ks_guard_transport_security();

-- 8. SELLER RATINGS & REVIEWS TABLE
create table if not exists public.seller_reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  seller_id uuid not null references auth.users(id) on delete cascade,
  buyer_id uuid not null references auth.users(id) on delete cascade,
  buyer_name text not null,
  rating integer not null check (rating between 1 and 5),
  comment text,
  created_at timestamptz not null default now(),
  unique (product_id, buyer_id)
);

create index if not exists idx_seller_reviews_seller on public.seller_reviews(seller_id);
alter table public.seller_reviews enable row level security;

drop policy if exists "reviews_select_all" on public.seller_reviews;
create policy "reviews_select_all" on public.seller_reviews
  for select using (true);

drop policy if exists "reviews_insert_own" on public.seller_reviews;
create policy "reviews_insert_own" on public.seller_reviews
  for insert to authenticated
  with check (buyer_id = auth.uid());

drop policy if exists "reviews_update_own" on public.seller_reviews;
create policy "reviews_update_own" on public.seller_reviews
  for update to authenticated
  using (buyer_id = auth.uid())
  with check (buyer_id = auth.uid());

drop policy if exists "reviews_delete_own_or_admin" on public.seller_reviews;
create policy "reviews_delete_own_or_admin" on public.seller_reviews
  for delete to authenticated
  using (
    buyer_id = auth.uid()
    or exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

create or replace function public.ks_guard_review_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  new.buyer_name := left(btrim(regexp_replace(coalesce(new.buyer_name, 'Buyer'), '[<>]', '', 'g')), 80);
  if new.comment is not null then
    new.comment := left(btrim(regexp_replace(new.comment, '[<>]', '', 'g')), 400);
  end if;
  if auth.uid() is not null then
    new.buyer_id := auth.uid();
    if new.buyer_id = new.seller_id then
      raise exception 'You cannot review your own listing.';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_ks_guard_review_security on public.seller_reviews;
create trigger trg_ks_guard_review_security
  before insert or update on public.seller_reviews
  for each row execute function public.ks_guard_review_security();

-- 9. SECURE UPI PAYMENT ORDERS & DIGITAL RECEIPT LEDGER
create table if not exists public.payment_orders (
  id uuid primary key default gen_random_uuid(),
  order_code text unique not null,
  product_id uuid references public.products(id) on delete set null,
  product_title text not null,
  seller_id uuid not null references auth.users(id) on delete cascade,
  buyer_id uuid not null references auth.users(id) on delete cascade,
  buyer_name text not null,
  seller_name text not null,
  quantity numeric(12,2) not null check (quantity > 0),
  unit text not null,
  unit_price numeric(12,2) not null check (unit_price > 0),
  total_amount numeric(12,2) not null check (total_amount > 0),
  payee_upi_id text not null,
  utr_number text,
  payment_status text not null default 'initiated' check (payment_status in ('initiated', 'utr_submitted', 'verified', 'disputed', 'cancelled')),
  buyer_note text,
  dispute_reason text,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_payment_orders_buyer on public.payment_orders(buyer_id, created_at desc);
create index if not exists idx_payment_orders_seller on public.payment_orders(seller_id, created_at desc);
alter table public.payment_orders enable row level security;

drop policy if exists "payment_orders_select_party_or_admin" on public.payment_orders;
create policy "payment_orders_select_party_or_admin" on public.payment_orders
  for select to authenticated
  using (
    buyer_id = auth.uid()
    or seller_id = auth.uid()
    or exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

drop policy if exists "payment_orders_insert_buyer" on public.payment_orders;
create policy "payment_orders_insert_buyer" on public.payment_orders
  for insert to authenticated
  with check (buyer_id = auth.uid());

drop policy if exists "payment_orders_update_party_or_admin" on public.payment_orders;
create policy "payment_orders_update_party_or_admin" on public.payment_orders
  for update to authenticated
  using (
    buyer_id = auth.uid()
    or seller_id = auth.uid()
    or exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  )
  with check (
    buyer_id = auth.uid()
    or seller_id = auth.uid()
    or exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

create or replace function public.ks_guard_payment_order_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text;
  v_recent_count integer;
begin
  new.updated_at := now();
  new.product_title := left(btrim(regexp_replace(coalesce(new.product_title, ''), '[<>]', '', 'g')), 160);
  new.buyer_name := left(btrim(regexp_replace(coalesce(new.buyer_name, 'Buyer'), '[<>]', '', 'g')), 80);
  new.seller_name := left(btrim(regexp_replace(coalesce(new.seller_name, 'Seller'), '[<>]', '', 'g')), 80);
  new.payee_upi_id := lower(btrim(regexp_replace(coalesce(new.payee_upi_id, ''), '[<>[:space:]]', '', 'g')));

  if new.buyer_note is not null then
    new.buyer_note := left(btrim(regexp_replace(new.buyer_note, '[<>]', '', 'g')), 400);
  end if;
  if new.dispute_reason is not null then
    new.dispute_reason := left(btrim(regexp_replace(new.dispute_reason, '[<>]', '', 'g')), 400);
  end if;
  if new.utr_number is not null then
    new.utr_number := upper(btrim(regexp_replace(new.utr_number, '[^a-zA-Z0-9]', '', 'g')));
    if new.utr_number = '' then
      new.utr_number := null;
    elsif char_length(new.utr_number) < 8 or char_length(new.utr_number) > 30 then
      raise exception 'UTR / UPI Reference number must be 8 to 30 alphanumeric characters.';
    end if;
  end if;

  if new.payee_upi_id !~ '^[a-z0-9._-]{2,64}@[a-z0-9.-]{2,32}$' then
    raise exception 'Invalid payee UPI ID.';
  end if;

  if auth.uid() is null then
    return new;
  end if;

  select role into v_caller_role from public.profiles where id = auth.uid();

  if tg_op = 'INSERT' then
    new.buyer_id := auth.uid();
    if new.buyer_id = new.seller_id then
      raise exception 'You cannot create a payment order to yourself.';
    end if;

    -- Server-side total calculation prevents price tampering
    new.total_amount := round(new.quantity * new.unit_price, 2);
    if new.total_amount <= 0 or new.total_amount > 100000000 then
      raise exception 'Invalid payment total amount.';
    end if;

    -- Generate tamper-proof order code
    new.order_code := 'KS-PAY-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));

    -- Buyer can never self-verify a payment on insert
    if new.utr_number is not null then
      new.payment_status := 'utr_submitted';
    else
      new.payment_status := 'initiated';
    end if;
    new.verified_at := null;

    select count(*) into v_recent_count from public.payment_orders
    where buyer_id = auth.uid() and created_at > now() - interval '24 hours';
    if v_recent_count >= 15 then
      raise exception 'Daily payment order limit reached (15/day).';
    end if;

  elsif tg_op = 'UPDATE' then
    -- Immutable core invoice fields after creation
    new.order_code := old.order_code;
    new.buyer_id := old.buyer_id;
    new.seller_id := old.seller_id;
    new.quantity := old.quantity;
    new.unit_price := old.unit_price;
    new.total_amount := old.total_amount;
    new.payee_upi_id := old.payee_upi_id;

    -- Only seller or admin can mark payment verified
    if new.payment_status = 'verified' and old.payment_status <> 'verified' then
      if auth.uid() <> old.seller_id and coalesce(v_caller_role, '') <> 'admin' then
        raise exception 'Only the seller or admin can verify UPI payment receipt.';
      end if;
      new.verified_at := now();
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_payment_order_security on public.payment_orders;
create trigger trg_ks_guard_payment_order_security
  before insert or update on public.payment_orders
  for each row execute function public.ks_guard_payment_order_security();

-- Safe notification helper on payment updates (non-blocking)
create or replace function public.ks_notify_payment_order()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  begin
    if tg_op = 'INSERT' and new.payment_status = 'utr_submitted' then
      insert into public.notifications (user_id, title, body, is_read)
      values (
        new.seller_id,
        'નવી UPI ચૂકવણી ચકાસણી (' || new.order_code || ')',
        new.buyer_name || ' એ ₹' || new.total_amount || ' (UTR: ' || coalesce(new.utr_number, '-') || ') મોકલ્યા છે. બેંકમાં ચેક કરી મંજૂર કરો.',
        false
      );
    elsif tg_op = 'UPDATE' and new.payment_status = 'verified' and old.payment_status <> 'verified' then
      insert into public.notifications (user_id, title, body, is_read)
      values (
        new.buyer_id,
        'ચૂકવણી મંજૂર થઈ (' || new.order_code || ')',
        new.seller_name || ' એ ₹' || new.total_amount || ' ની UPI ચૂકવણી સ્વીકારી લીધી છે. ડિજિટલ રસીદ તૈયાર છે.',
        false
      );
    elsif tg_op = 'UPDATE' and new.payment_status = 'utr_submitted' and old.payment_status = 'initiated' then
      insert into public.notifications (user_id, title, body, is_read)
      values (
        new.seller_id,
        'UPI UTR નંબર મળ્યો (' || new.order_code || ')',
        new.buyer_name || ' એ ₹' || new.total_amount || ' માટે UTR ' || coalesce(new.utr_number, '-') || ' સબમિટ કર્યો છે.',
        false
      );
    end if;
  exception when others then
    null;
  end;
  return new;
end;
$$;

drop trigger if exists trg_ks_notify_payment_order on public.payment_orders;
create trigger trg_ks_notify_payment_order
  after insert or update on public.payment_orders
  for each row execute function public.ks_notify_payment_order();
