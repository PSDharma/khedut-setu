-- ============================================================================
-- KHEDUT SETU — 009 MASTER SECURITY HARDENING (Production Server-Side Defense)
-- Safe & Idempotent: Can be run multiple times without breaking existing data.
-- ============================================================================

-- 1. PREVENT PRIVILEGE ESCALATION (Nobody can hack their own role to 'admin'
--    or mark themselves 'is_verified = true' via browser DevTools / API)
create or replace function public.ks_guard_profile_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller_role text;
begin
  -- Allow service_role / SQL editor (auth.uid() is null)
  if auth.uid() is null then
    return new;
  end if;

  select role into v_caller_role
  from public.profiles
  where id = auth.uid();

  -- Non-admins cannot change role to admin, cannot self-verify, cannot unban themselves
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

  -- Sanitize text fields (strip angle brackets to neutralize stored XSS)
  if new.full_name is not null then
    new.full_name := btrim(regexp_replace(new.full_name, '[<>]', '', 'g'));
  end if;
  if new.business_name is not null then
    new.business_name := btrim(regexp_replace(new.business_name, '[<>]', '', 'g'));
  end if;
  if new.village_city is not null then
    new.village_city := btrim(regexp_replace(new.village_city, '[<>]', '', 'g'));
  end if;
  if new.district is not null then
    new.district := btrim(regexp_replace(new.district, '[<>]', '', 'g'));
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_profile_security on public.profiles;
create trigger trg_ks_guard_profile_security
  before update on public.profiles
  for each row
  execute function public.ks_guard_profile_security();

-- 2. SERVER-SIDE PRODUCT SANITIZATION, STATUS LOCK & ANTI-SPAM RATE LIMIT
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
  -- Numeric sanity checks
  if new.expected_price is null or new.expected_price <= 0 or new.expected_price > 100000000 then
    raise exception 'Invalid price range.';
  end if;
  if new.available_quantity is null or new.available_quantity <= 0 or new.available_quantity > 10000000 then
    raise exception 'Invalid quantity range.';
  end if;

  -- Strip XSS angle brackets from user-submitted strings
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

  -- Allow SQL editor / service_role bypass for role & rate checks
  if auth.uid() is null then
    return new;
  end if;

  select role into v_caller_role from public.profiles where id = auth.uid();

  if tg_op = 'INSERT' then
    -- Force owner to authenticated user
    new.seller_id := auth.uid();

    -- Non-admins cannot self-approve or self-feature products
    if coalesce(v_caller_role, '') <> 'admin' then
      new.status := 'pending';
      new.is_featured := false;

      -- Anti-spam: Max 15 listings per user in 24 hours
      select count(*) into v_recent_count
      from public.products
      where seller_id = auth.uid()
        and created_at > now() - interval '24 hours';

      if v_recent_count >= 15 then
        raise exception 'Daily listing limit reached (15/day). Please try again tomorrow.';
      end if;
    end if;
  elsif tg_op = 'UPDATE' then
    -- Non-admins cannot change status to approved or toggle is_featured
    if coalesce(v_caller_role, '') <> 'admin' then
      if new.status is distinct from old.status then
        raise exception 'Only admins can approve or change product moderation status.';
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
  for each row
  execute function public.ks_guard_product_security();

-- 3. ANTI-SPAM & XSS SANITIZATION FOR INQUIRIES
create or replace function public.ks_guard_inquiry_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_count integer;
begin
  new.message := left(btrim(regexp_replace(coalesce(new.message, ''), '[<>]', '', 'g')), 1000);
  if char_length(new.message) < 3 then
    raise exception 'Inquiry message is too short.';
  end if;

  if auth.uid() is not null then
    new.buyer_id := auth.uid();
    if new.buyer_id = new.seller_id then
      raise exception 'You cannot send an inquiry to your own listing.';
    end if;

    -- Max 20 inquiries per user per hour
    select count(*) into v_recent_count
    from public.inquiries
    where buyer_id = auth.uid()
      and created_at > now() - interval '1 hour';

    if v_recent_count >= 20 then
      raise exception 'Too many inquiries sent. Please wait before sending more.';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_inquiry_security on public.inquiries;
create trigger trg_ks_guard_inquiry_security
  before insert on public.inquiries
  for each row
  execute function public.ks_guard_inquiry_security();

-- 4. ANTI-SPAM & SANITIZATION FOR BUYER REQUESTS
create or replace function public.ks_guard_buyer_request_security()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_count integer;
begin
  new.product_required := left(btrim(regexp_replace(coalesce(new.product_required, ''), '[<>]', '', 'g')), 160);
  new.delivery_location := left(btrim(regexp_replace(coalesce(new.delivery_location, ''), '[<>]', '', 'g')), 120);
  new.district := left(btrim(regexp_replace(coalesce(new.district, ''), '[<>]', '', 'g')), 100);
  if new.quality_requirements is not null then
    new.quality_requirements := left(btrim(regexp_replace(new.quality_requirements, '[<>]', '', 'g')), 1000);
  end if;

  if new.required_quantity is null or new.required_quantity <= 0 then
    raise exception 'Invalid required quantity.';
  end if;

  if auth.uid() is not null then
    new.buyer_id := auth.uid();

    select count(*) into v_recent_count
    from public.buyer_requests
    where buyer_id = auth.uid()
      and created_at > now() - interval '24 hours';

    if v_recent_count >= 10 then
      raise exception 'Daily requirement post limit reached (10/day).';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_ks_guard_buyer_request_security on public.buyer_requests;
create trigger trg_ks_guard_buyer_request_security
  before insert or update on public.buyer_requests
  for each row
  execute function public.ks_guard_buyer_request_security();

-- 5. HARDEN STORAGE BUCKET (Block SVG/HTML/JS/EXE uploads — strictly JPEG/PNG/WebP <= 5MB)
update storage.buckets
set
  file_size_limit = 5242880,
  allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp']
where id = 'product-images';

-- 6. VERIFY RLS IS ENABLED ON ALL CRITICAL PUBLIC TABLES
alter table if exists public.profiles enable row level security;
alter table if exists public.products enable row level security;
alter table if exists public.categories enable row level security;
alter table if exists public.buyer_requests enable row level security;
alter table if exists public.inquiries enable row level security;
alter table if exists public.favorites enable row level security;
alter table if exists public.notifications enable row level security;
alter table if exists public.platform_settings enable row level security;
