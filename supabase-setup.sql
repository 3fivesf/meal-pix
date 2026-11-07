-- Meal Pix: shared household setup for Supabase
-- Paste this whole file into Supabase > SQL Editor > New query, then click Run.
-- Safe to run again: it only creates what is missing and refreshes the rules.

create extension if not exists pgcrypto;

-- ---------- Tables ----------

create table if not exists public.households (
  id          uuid primary key default gen_random_uuid(),
  name        text not null default 'Our kitchen' check (char_length(name) between 1 and 60),
  invite_code text not null unique default upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 8)),
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now()
);

create table if not exists public.members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id      uuid not null references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 30),
  color        text not null default 'sky' check (color ~ '^[a-z]{2,12}$'),
  role         text not null default 'member' check (role in ('owner', 'member')),
  joined_at    timestamptz not null default now(),
  primary key (household_id, user_id)
);

-- One row per meal. "data" holds name, color, border, photos, ingredients, amounts.
create table if not exists public.meals (
  household_id uuid not null references public.households(id) on delete cascade,
  id           text not null check (char_length(id) between 1 and 64),
  data         jsonb not null check (pg_column_size(data) < 20000),
  updated_at   timestamptz not null default now(),
  updated_by   uuid default auth.uid(),
  primary key (household_id, id)
);

create table if not exists public.favorites (
  household_id uuid not null references public.households(id) on delete cascade,
  meal_id      text not null,
  user_id      uuid not null references auth.users(id) on delete cascade,
  created_at   timestamptz not null default now(),
  primary key (household_id, meal_id, user_id)
);

-- Each person's week: { "0": { "l": mealId, "d": mealId }, ... }
create table if not exists public.plans (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id      uuid not null references auth.users(id) on delete cascade,
  plan         jsonb not null default '{}'::jsonb check (pg_column_size(plan) < 20000),
  updated_at   timestamptz not null default now(),
  primary key (household_id, user_id)
);

-- Shared grocery ticks and remembered ingredients.
create table if not exists public.household_state (
  household_id uuid primary key references public.households(id) on delete cascade,
  checked      jsonb not null default '{}'::jsonb check (pg_column_size(checked) < 50000),
  ings         jsonb not null default '[]'::jsonb check (pg_column_size(ings) < 50000),
  updated_at   timestamptz not null default now()
);

-- ---------- Who belongs where ----------

create or replace function public.is_member(hid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.members where household_id = hid and user_id = auth.uid());
$$;

create or replace function public.is_owner(hid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.members where household_id = hid and user_id = auth.uid() and role = 'owner');
$$;

-- ---------- Access rules: only members of a household can see or change it ----------

alter table public.households      enable row level security;
alter table public.members         enable row level security;
alter table public.meals           enable row level security;
alter table public.favorites       enable row level security;
alter table public.plans           enable row level security;
alter table public.household_state enable row level security;

drop policy if exists "members read household"   on public.households;
drop policy if exists "owner renames household"  on public.households;
create policy "members read household"  on public.households for select to authenticated using (public.is_member(id));
create policy "owner renames household" on public.households for update to authenticated using (public.is_owner(id)) with check (public.is_owner(id));

drop policy if exists "members see each other"      on public.members;
drop policy if exists "edit own name and color"     on public.members;
drop policy if exists "leave or owner removes"      on public.members;
create policy "members see each other"  on public.members for select to authenticated using (public.is_member(household_id));
create policy "edit own name and color" on public.members for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
-- People can change only their own name and color, never their role.
revoke update on public.members from authenticated, anon;
grant update (display_name, color) on public.members to authenticated;
create policy "leave or owner removes"  on public.members for delete to authenticated using (user_id = auth.uid() or public.is_owner(household_id));

drop policy if exists "members use meals" on public.meals;
create policy "members use meals" on public.meals for all to authenticated using (public.is_member(household_id)) with check (public.is_member(household_id));

drop policy if exists "members read favorites" on public.favorites;
drop policy if exists "save own favorites"     on public.favorites;
drop policy if exists "remove own favorites"   on public.favorites;
create policy "members read favorites" on public.favorites for select to authenticated using (public.is_member(household_id));
create policy "save own favorites"     on public.favorites for insert to authenticated with check (user_id = auth.uid() and public.is_member(household_id));
create policy "remove own favorites"   on public.favorites for delete to authenticated using (user_id = auth.uid() and public.is_member(household_id));

-- Members can plan for each other (the "Picking for" switch), but only inside their household.
drop policy if exists "members use plans" on public.plans;
create policy "members use plans" on public.plans for all to authenticated
  using (public.is_member(household_id))
  with check (public.is_member(household_id) and exists (select 1 from public.members m where m.household_id = plans.household_id and m.user_id = plans.user_id));

drop policy if exists "members use shared state" on public.household_state;
create policy "members use shared state" on public.household_state for all to authenticated using (public.is_member(household_id)) with check (public.is_member(household_id));

-- ---------- Actions the app calls ----------

create or replace function public.create_household(p_name text, p_display_name text, p_color text)
returns public.households language plpgsql security definer set search_path = public as $$
declare h public.households;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  insert into public.households (name, created_by)
    values (coalesce(nullif(trim(p_name), ''), 'Our kitchen'), auth.uid()) returning * into h;
  insert into public.members (household_id, user_id, display_name, color, role)
    values (h.id, auth.uid(), trim(p_display_name), coalesce(nullif(p_color, ''), 'tomato'), 'owner');
  insert into public.household_state (household_id) values (h.id);
  return h;
end $$;

create or replace function public.join_household(p_code text, p_display_name text, p_color text)
returns uuid language plpgsql security definer set search_path = public as $$
declare hid uuid; n int;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select id into hid from public.households where invite_code = upper(trim(p_code));
  if hid is null then raise exception 'That invite code doesn''t match a household'; end if;
  select count(*) into n from public.members where household_id = hid;
  if n >= 8 and not public.is_member(hid) then raise exception 'This household is full (8 people)'; end if;
  insert into public.members (household_id, user_id, display_name, color)
    values (hid, auth.uid(), trim(p_display_name), coalesce(nullif(p_color, ''), 'sky'))
    on conflict (household_id, user_id) do update set display_name = excluded.display_name;
  return hid;
end $$;

-- Owner can make a new invite code (the old one stops working).
create or replace function public.new_invite_code(hid uuid)
returns text language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if not public.is_owner(hid) then raise exception 'Only the household owner can do that'; end if;
  c := upper(substr(encode(gen_random_bytes(6), 'hex'), 1, 8));
  update public.households set invite_code = c where id = hid;
  return c;
end $$;

-- Deletes the signed-in person's account. Households they own pass to the next member,
-- or are deleted if nobody else is in them. The app removes photos first.
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path = public as $$
declare r record; heir uuid;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  for r in select household_id from public.members where user_id = auth.uid() and role = 'owner' loop
    select user_id into heir from public.members
      where household_id = r.household_id and user_id <> auth.uid() order by joined_at limit 1;
    if heir is null then
      delete from public.households where id = r.household_id;
    else
      update public.members set role = 'owner' where household_id = r.household_id and user_id = heir;
    end if;
  end loop;
  delete from auth.users where id = auth.uid();
end $$;

revoke all on function public.create_household(text, text, text) from public, anon;
revoke all on function public.join_household(text, text, text)   from public, anon;
revoke all on function public.new_invite_code(uuid)              from public, anon;
revoke all on function public.delete_my_account()                from public, anon;
grant execute on function public.create_household(text, text, text) to authenticated;
grant execute on function public.join_household(text, text, text)   to authenticated;
grant execute on function public.new_invite_code(uuid)              to authenticated;
grant execute on function public.delete_my_account()                to authenticated;

-- ---------- Photos: private bucket, one folder per household ----------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do nothing;

create or replace function public.photo_household(object_name text)
returns uuid language plpgsql immutable as $$
begin
  return split_part(object_name, '/', 1)::uuid;
exception when others then
  return null;
end $$;

drop policy if exists "household photos read"   on storage.objects;
drop policy if exists "household photos add"    on storage.objects;
drop policy if exists "household photos change" on storage.objects;
drop policy if exists "household photos remove" on storage.objects;
create policy "household photos read"   on storage.objects for select to authenticated using (bucket_id = 'photos' and public.is_member(public.photo_household(name)));
create policy "household photos add"    on storage.objects for insert to authenticated with check (bucket_id = 'photos' and public.is_member(public.photo_household(name)));
create policy "household photos change" on storage.objects for update to authenticated using (bucket_id = 'photos' and public.is_member(public.photo_household(name)));
create policy "household photos remove" on storage.objects for delete to authenticated using (bucket_id = 'photos' and public.is_member(public.photo_household(name)));

-- ---------- Live updates between phones ----------

do $$
declare t text;
begin
  foreach t in array array['meals', 'favorites', 'plans', 'household_state', 'members'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
