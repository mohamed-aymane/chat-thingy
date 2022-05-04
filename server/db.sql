
create table "user" (
    id serial primary key,
    public_key bytea not null
);

create table challenge (
    "user" int primary key,
    key bytea not null,
    timestamp bigint not null,
    constraint fk_user foreign key("user") references "user" (id) on delete cascade
);

create table message (
    id serial,
    "user" int not null,
    message bytea not null,
    timestamp bigint not null,
    primary key(id, "user"),
    constraint fk_muser foreign key("user") references "user" (id) on delete cascade
);


create or replace function new_message_notification() returns trigger as $$
    declare
    begin

    perform pg_notify(encode(NEW.user, 'base64'), NEW.id::text);
    
    return null;
    end;
$$ language plpgsql;

create or replace trigger trigger_my_table_update
  after insert
  on message
  for each row
  execute procedure new_message_notification();
