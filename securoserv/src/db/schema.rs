// Diesel schema definition for Securoserv database
use diesel::table;
use diesel::allow_tables_to_appear_in_same_query;

table! {
    sessions (id) {
        id -> Text,
        session_uuid -> Text,
        license_key -> Text,
        hardware_id -> Nullable<Text>,
        client_public_key -> Binary,
        client_verifying_key -> Text,
        client_kyber_public -> Text,
        created_at -> BigInt,
        last_heartbeat -> BigInt,
        is_authenticated -> Bool,
    }
}

table! {
    licenses (id) {
        id -> Text,
        license_key -> Text,
        created_at -> BigInt,
        expires_at -> BigInt,
        is_revoked -> Bool,
        max_connections -> Integer,
        license_type -> Text,
    }
}

table! {
    bans (id) {
        id -> Text,
        banned_entity -> Text,
        ban_type -> Text,
        reason -> Text,
        created_at -> BigInt,
        banned_by -> Nullable<Text>,
        reporter_session -> Nullable<Text>,
        reported_session -> Nullable<Text>,
        evidence -> Nullable<Text>,
        status -> Text,
    }
}

table! {
    messages (id) {
        id -> Text,
        sender_session -> Text,
        recipient_session -> Nullable<Text>,
        content -> Text,
        created_at -> BigInt,
        is_delivered -> Bool,
        delivered_at -> Nullable<BigInt>,
    }
}

table! {
    audit_logs (id) {
        id -> Text,
        session_uuid -> Nullable<Text>,
        event_type -> Text,
        event_data -> Text,
        created_at -> BigInt,
        ip_address -> Nullable<Text>,
    }
}

// Foreign key relationships
allow_tables_to_appear_in_same_query!(
    sessions,
    licenses,
    bans,
    messages,
    audit_logs,
);
