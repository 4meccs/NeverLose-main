use std::collections::HashMap;
use std::net::SocketAddr;

use axum::{
    Router,
    extract::{
        ConnectInfo, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use anyhow::Context;
use base64::Engine as _;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::{AUTH_DATA, AUTH_MESSAGE};
use crate::data::KEY_BIN;
use crate::module_builder::LogEntryWithContent;
use crate::response::{self, entry_type_id_from_name, entry_type_name};
use crate::storage::LogEntryData;
use crate::utils;
use crate::{AppState, module_builder};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/getitem", get(getitem_handler))
        .fallback(any(ws_upgrade))
        .with_state(state)
}

async fn getitem_handler(Query(params): Query<HashMap<String, String>>) -> Response {
    let code = params.get("c").map(|s| s.as_str()).unwrap_or("");
    tracing::info!("[WS/HTTP] GET /getitem c={}", utils::preview_text(code, 64));

    match nl_parser::pipeline::encrypt(&[]) {
        Ok(encrypted) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, encrypted.len().to_string())
            .body(axum::body::Body::from(encrypted))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(e) => {
            tracing::error!("[WS/HTTP] /getitem encryption failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn ws_upgrade(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    tracing::info!("[WS] New WebSocket upgrade request from {}", addr);
    ws.max_message_size(50 * 1024 * 1024)
        .on_upgrade(move |socket| handle_ws(socket, state, addr))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, addr: SocketAddr) {
    let first = socket.recv().await;
    let token = match first {
        Some(Ok(ref msg)) => {
            tracing::info!("[WS] <- First message: {}", msg_summary(msg));
            match msg {
                Message::Text(t) => t.lines().next().unwrap_or("").trim().to_string(),
                _ => String::new(),
            }
        }
        Some(Err(e)) => {
            tracing::warn!("[WS] <- Recv error on first message: {e}");
            return;
        }
        None => {
            tracing::info!("[WS] <- Client disconnected before sending");
            return;
        }
    };

    if token.is_empty() {
        tracing::warn!("[WS] No token found in first message, closing");
        return;
    }

    tracing::info!("[WS] Token from first message: {token}");

    state
        .ip_tokens
        .write()
        .await
        .insert(addr.ip(), token.clone());

    let username = state.storage.username().await;

    let auth = json!({
        "Type": "Auth",
        "Message": AUTH_MESSAGE,
        "Data": AUTH_DATA,
    });
    tracing::info!("[WS] -> Auth JSON: {}", auth);
    if socket
        .send(Message::Text(auth.to_string().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send auth frame");
        return;
    }

    let module_bin = if let Some(ref raw) = state.raw_module {
        tracing::info!("[WS] Using raw module override ({} bytes)", raw.len());
        raw.clone()
    } else {
        match build_user_module(&state, &username).await {
            Ok(bin) => bin,
            Err(e) => {
                tracing::error!("[WS] Failed to build module for {}: {:?}", username, e);
                return;
            }
        }
    };

    tracing::info!("[WS] -> Module blob ({} bytes)", module_bin.len());
    if socket
        .send(Message::Binary(module_bin.into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send module blob");
        return;
    }

    if socket
        .send(Message::Binary(KEY_BIN.to_vec().into()))
        .await
        .is_err()
    {
        tracing::error!("[WS] Failed to send key blob");
        return;
    }

    let live_conn_id = Uuid::new_v4();
    let (live_tx, mut live_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    state
        .live_replies
        .write()
        .await
        .entry(token.clone())
        .or_default()
        .insert(live_conn_id, live_tx);
    let mut msg_count = 0u32;
    loop {
        tokio::select! {
            maybe_reply = live_rx.recv() => {
                match maybe_reply {
                    Some(reply) => send_reply(&mut socket, &reply, "[WS] Live").await,
                    None => break,
                }
            }
            maybe_msg = socket.recv() => {
                let Some(msg) = maybe_msg else {
                    break;
                };

                match msg {
                    Ok(msg) => {
                        if matches!(msg, Message::Close(_)) {
                            tracing::info!("[WS] <- Close: {}", msg_summary(&msg));
                            break;
                        }
                        msg_count += 1;

                        if let Message::Binary(ref data) = msg {
                            handle_binary_msg(&state, &username, data, msg_count, &mut socket).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[WS] <- Error: {e}");
                        break;
                    }
                }
            }
        }
    }

    unregister_live_reply(&state, &token, live_conn_id).await;
    let _ = state.shutdown_tx.send(true);

    tracing::info!(
        "[WS] Disconnected (received {} post-auth messages)",
        msg_count
    );
}

async fn build_user_module(state: &AppState, username: &str) -> anyhow::Result<Vec<u8>> {
    let user_data = state.storage.user_data().await;
    let log_entries = state.storage.log_entries().await;

    let mut entries_with_content: Vec<LogEntryWithContent> = Vec::new();
    for entry in &log_entries {
        let content = if entry.entry_type == "Script" || entry.entry_type == "Style" {
            state.storage.read_entry_content(entry.entry_id).await?
        } else {
            None
        };
        entries_with_content.push(LogEntryWithContent {
            entry_id: entry.entry_id,
            timestamp: entry.timestamp,
            entry_type: entry.entry_type.clone(),
            author: entry.author.clone(),
            name: entry.name.clone(),
            content,
            deleted: entry.deleted_at.is_some(),
        });
    }

    let user_languages = state.language_translations.read().await.clone();

    module_builder::build_module_bin(
        &state.base_module,
        username,
        user_data.type7_blob.as_deref(),
        user_data.last_loaded_config_id,
        user_data.last_loaded_style_id,
        &entries_with_content,
        &user_languages,
        user_data.valid_until,
    )
}

async fn handle_binary_msg(
    state: &AppState,
    username: &str,
    data: &[u8],
    msg_num: u32,
    socket: &mut WebSocket,
) {
    use nl_parser::pipeline;

    let prefix = format!("[WS] Msg #{msg_num}");

    let decompressed = match pipeline::decrypt(data) {
        Ok(decrypted) => match pipeline::decompress(&decrypted) {
            Ok(d) => d,
            Err(_) => {
                tracing::debug!("{prefix} decrypt ok but decompress failed");
                return;
            }
        },
        Err(_) => {
            tracing::debug!("{prefix} decrypt failed, ignoring");
            return;
        }
    };

    match crate::client_msg::parse(&decompressed) {
        Ok(msg) => {
            if let crate::client_msg::ClientMsg::StateBlob { payload } = &msg {
                if let Err(e) = save_type7_blob(state, payload, &prefix).await {
                    tracing::error!("{prefix} failed to persist type7 blob: {e}");
                }
            }
            let reply = handle_client_msg(state, username, &msg, &prefix).await;
            if let Some(reply_bytes) = reply {
                send_reply(socket, &reply_bytes, &prefix).await;
            }
        }
        Err(e) => {
            tracing::warn!(
                "{prefix} parse error: {e}, hex: {}",
                utils::hex_dump(&decompressed, 128)
            );
        }
    }
}

async fn send_reply(socket: &mut WebSocket, flatbuffer: &[u8], prefix: &str) {
    use nl_parser::pipeline;
    let compressed = pipeline::compress(flatbuffer);
    match pipeline::encrypt(&compressed) {
        Ok(encrypted) => {
            tracing::info!("{prefix} -> Reply ({} bytes)", encrypted.len());
            if socket
                .send(Message::Binary(encrypted.into()))
                .await
                .is_err()
            {
                tracing::error!("{prefix} Failed to send reply");
            }
        }
        Err(e) => {
            tracing::error!("{prefix} Failed to encrypt reply: {e}");
        }
    }
}

async fn unregister_live_reply(state: &AppState, token: &str, conn_id: Uuid) {
    let mut live_replies = state.live_replies.write().await;
    if let Some(conns) = live_replies.get_mut(token) {
        conns.remove(&conn_id);
        if conns.is_empty() {
            live_replies.remove(token);
        }
    }
}

async fn handle_client_msg(
    state: &AppState,
    username: &str,
    msg: &crate::client_msg::ClientMsg,
    prefix: &str,
) -> Option<Vec<u8>> {
    use crate::client_msg::ClientMsg;

    match msg {
        ClientMsg::Init { steam_id } => {
            tracing::info!("{prefix} Init steam_id={steam_id} user={username}");
            None
        }

        ClientMsg::ConfigAck { entry_id } => {
            tracing::info!("{prefix} ConfigAck entry_id={entry_id}");

            let log_entry = match state.storage.get_log_entry(*entry_id as i32).await {
                Some(row) => row,
                None => {
                    tracing::warn!(
                        "{prefix} ConfigAck entry_id={entry_id} had no matching log entry"
                    );
                    return None;
                }
            };

            if log_entry.entry_type != "Config" {
                tracing::info!(
                    "{prefix} ConfigAck entry_id={entry_id} ignored non-config type={}",
                    log_entry.entry_type
                );
                return None;
            }

            let content = match state
                .storage
                .read_entry_content(*entry_id as i32)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    tracing::warn!("{prefix} ConfigAck entry_id={entry_id} had no stored config");
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to load config for ConfigAck: {e}");
                    return None;
                }
            };

            if let Err(e) = state
                .storage
                .update_last_loaded_entry("Config", *entry_id as i32)
                .await
            {
                tracing::error!("{prefix} failed to remember last loaded config: {e}");
            }

            match response::build_case11_response(*entry_id, &content) {
                Ok(reply) => Some(reply),
                Err(e) => {
                    tracing::error!("{prefix} failed to build case11 load reply: {e}");
                    None
                }
            }
        }

        ClientMsg::ShareClick { entry_type } => {
            tracing::info!(
                "{prefix} ShareClick entry_type={}",
                share_entry_type_name(*entry_type)
            );
            None
        }

        ClientMsg::StateBlob { .. } => None,

        ClientMsg::LanguageAck { lang_code } => {
            let translations_guard = state.language_translations.read().await;
            let Some(value) = translations_guard.get(lang_code) else {
                tracing::warn!("{prefix} LanguageAck: no translations for {lang_code}");
                return None;
            };
            let json_bytes = match nl_parser::module::serialize_translations_json(value) {
                Ok(b) => b,
                Err(e) => { tracing::error!("{prefix} LanguageAck: serialize: {e}"); return None; }
            };
            let json_str = match std::str::from_utf8(&json_bytes) {
                Ok(s) => s,
                Err(e) => { tracing::error!("{prefix} LanguageAck: UTF-8: {e}"); return None; }
            };
            match response::build_language_ack_response_type12(lang_code, json_str) {
                Ok(reply) => {
                    tracing::info!("{prefix} LanguageAck: type12 sent for {lang_code} {}B", json_str.len());
                    Some(reply)
                }
                Err(e) => { tracing::error!("{prefix} LanguageAck: build: {e}"); None }
            }
        }

        ClientMsg::CreateEntry {
            name,
            entry_type,
            expected_count: _,
            content,
        } => {
            let type_str = entry_type_name(*entry_type);

            let entry_id = match state.storage.next_entry_id().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} failed to get next entry_id: {e}");
                    return None;
                }
            };

            let now_ts = utils::unix_timestamp();

            let log_entry = LogEntryData {
                entry_id,
                timestamp: now_ts,
                entry_type: type_str.to_string(),
                author: username.to_string(),
                name: name.clone(),
                created_at: utils::now_iso(),
                deleted_at: None,
            };

            if let Err(e) = state.storage.add_log_entry(log_entry).await {
                tracing::error!("{prefix} failed to create log entry: {e}");
                return None;
            }

            let initial_content = content.as_deref().unwrap_or("");
            let mut actual_content = match state.storage.read_entry_content(entry_id).await {
                Ok(Some(existing)) if !existing.is_empty() => {
                    tracing::info!(
                        "{prefix} Picked up existing file content for {type_str} '{name}'"
                    );
                    existing
                }
                _ => {
                    if let Err(e) = state
                        .storage
                        .write_entry_content(entry_id, initial_content)
                        .await
                    {
                        tracing::error!("{prefix} failed to write {type_str} content: {e}");
                        return None;
                    }
                    initial_content.to_string()
                }
            };

            if type_str == "Language" && !actual_content.is_empty() {
                if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&actual_content) {
                    let lang_code = name.clone();

                    let base_lang = value
                        .get("info")
                        .and_then(|i| i.get("base_lang"))
                        .and_then(|b| b.as_str())
                        .map(|s| s.to_string());
                    let has_strings = value
                        .get("strings")
                        .and_then(|s| s.as_object())
                        .map(|o| !o.is_empty())
                        .unwrap_or(false);

                    if !has_strings {
                        if let Some(ref base) = base_lang {
                            let translations_guard = state.language_translations.read().await;
                            if let Some(base_value) = translations_guard.get(base) {
                                if let Some(base_strings) = base_value.get("strings").cloned() {
                                    if let Some(obj) = value.as_object_mut() {
                                        obj.insert("strings".to_string(), base_strings);
                                        tracing::info!("{prefix} Auto-filled strings from base lang={base}");
                                    }
                                }
                            }
                        }
                        actual_content = serde_json::to_string(&value)
                            .unwrap_or_else(|_| actual_content.clone());
                    }

                    state
                        .language_translations
                        .write()
                        .await
                        .insert(lang_code.clone(), value);
                    tracing::info!(
                        "{prefix} Cached language translations for code={lang_code}"
                    );
                } else {
                    tracing::warn!("{prefix} Language content is not valid JSON for '{name}'");
                }
            }

            tracing::info!(
                "{prefix} Created entry_id={entry_id} type={type_str} name={name:?}"
            );

            if type_str == "Language" {
                let eng_name = utils::extract_json_str(&actual_content, &["info", "full_name"])
                    .unwrap_or_else(|| name.to_string());
                let nat_name = utils::extract_json_str(&actual_content, &["info", "loc_name"])
                    .unwrap_or_else(|| eng_name.clone());
                match response::build_language_create_response(
                    entry_id as u32,
                    now_ts as u32,
                    name,
                    &eng_name,
                    &nat_name,
                    &actual_content,
                ) {
                    Ok(reply) => {
                        tracing::info!("{prefix} Language create via type3/langtable for {name}");
                        Some(reply)
                    }
                    Err(e) => {
                        tracing::error!("{prefix} failed to build language create response: {e}");
                        None
                    }
                }
            } else {
                match response::build_create_response(
                    entry_id as u32,
                    now_ts as u32,
                    entry_type_id_from_name(type_str),
                    name,
                    username,
                    Some(&actual_content),
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} failed to build create response: {e}");
                        None
                    }
                }
            }
        }

        ClientMsg::UpdateEntry {
            entry_id,
            entry_type,
            content,
            name,
            timestamp,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!("{prefix} Update {type_str} entry_id={entry_id}");

            if let Some(ts) = timestamp {
                if let Err(e) = state
                    .storage
                    .update_log_entry_timestamp(*entry_id as i32, *ts as i32)
                    .await
                {
                    tracing::error!("{prefix} failed to update log entry timestamp: {e}");
                }
            }

            if let Some(new_name) = name {
                match state
                    .storage
                    .update_log_entry_name(*entry_id as i32, new_name)
                    .await
                {
                    Ok(true) => tracing::info!(
                        "{prefix} Renamed {type_str} {entry_id} to {new_name:?}"
                    ),
                    Ok(false) => {
                        tracing::warn!("{prefix} No log entry for {type_str} {entry_id}");
                    }
                    Err(e) => {
                        tracing::error!("{prefix} failed to update {type_str} name: {e}");
                    }
                }
            }

            if let Some(new_content) = content {
                if let Err(e) = state
                    .storage
                    .write_entry_content(*entry_id as i32, new_content)
                    .await
                {
                    tracing::error!("{prefix} failed to write {type_str} content: {e}");
                } else {
                    tracing::info!("{prefix} Updated {type_str} {entry_id}");
                    if type_str == "Language" {
                        let log = state.storage.log_entries().await;
                        if let Some(entry) = log.iter().find(|e| e.entry_id == *entry_id as i32) {
                            let code = &entry.name;
                            if let Ok(value) = serde_json::from_str::<serde_json::Value>(new_content) {
                                state.language_translations.write().await.insert(code.clone(), value);
                                tracing::info!("{prefix} Updated translations cache for {code}");
                            }
                        }
                    }
                }
            }

            None
        }

        ClientMsg::DuplicateEntry {
            entry_id,
            entry_type,
            name,
        } => {
            let type_str = entry_type_name(*entry_type);
            tracing::info!("{prefix} Duplicate entry_id={entry_id}");

            let new_entry_id = match state.storage.next_entry_id().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("{prefix} failed to get next entry_id for duplicate: {e}");
                    return None;
                }
            };

            let now_ts = utils::unix_timestamp();

            let (source_author, source_name) = match state.storage.get_log_entry(*entry_id as i32).await {
                Some(entry) => (entry.author, entry.name),
                None => {
                    tracing::warn!("{prefix} duplicate source log entry_id={entry_id} not found; using current user as author");
                    (username.to_string(), type_str.to_string())
                }
            };

            let source_content = match state
                .storage
                .read_entry_content(*entry_id as i32)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    tracing::warn!(
                        "{prefix} duplicate source {type_str} entry_id={entry_id} has no content"
                    );
                    return None;
                }
                Err(e) => {
                    tracing::error!("{prefix} failed to load duplicate source: {e}");
                    return None;
                }
            };

            let duplicate_name = name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or(source_name);

            if let Err(e) = state
                .storage
                .write_entry_content(new_entry_id, &source_content)
                .await
            {
                tracing::error!("{prefix} failed to write duplicate content: {e}");
                return None;
            }

            let log_entry = LogEntryData {
                entry_id: new_entry_id,
                timestamp: now_ts,
                entry_type: type_str.to_string(),
                author: source_author.clone(),
                name: duplicate_name.clone(),
                created_at: utils::now_iso(),
                deleted_at: None,
            };

            if let Err(e) = state.storage.add_log_entry(log_entry).await {
                tracing::error!("{prefix} failed to create duplicate log entry: {e}");
                return None;
            }

            if type_str == "Language" {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&source_content) {
                    state.language_translations.write().await.insert(duplicate_name.clone(), value);
                }
            }

            tracing::info!(
                "{prefix} Duplicated entry_id={entry_id} -> {new_entry_id} type={type_str} name={duplicate_name:?}"
            );

            if type_str == "Language" {
                let eng_name = utils::extract_json_str(&source_content, &["info", "full_name"])
                    .unwrap_or_else(|| duplicate_name.clone());
                let nat_name = utils::extract_json_str(&source_content, &["info", "loc_name"])
                    .unwrap_or_else(|| eng_name.clone());
                match response::build_language_create_response(
                    new_entry_id as u32,
                    now_ts as u32,
                    &duplicate_name,
                    &eng_name,
                    &nat_name,
                    &source_content,
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} failed to build duplicate response: {e}");
                        None
                    }
                }
            } else {
                match response::build_create_response(
                    new_entry_id as u32,
                    now_ts as u32,
                    entry_type_id_from_name(type_str),
                    &duplicate_name,
                    &source_author,
                    Some(&source_content),
                ) {
                    Ok(reply) => Some(reply),
                    Err(e) => {
                        tracing::error!("{prefix} failed to build duplicate response: {e}");
                        None
                    }
                }
            }
        }

        ClientMsg::DeleteEntry {
            entry_id,
            entry_type,
            action,
            raw_payload,
        } => {
            let type_str = entry_type_name(*entry_type);
            let extra = crate::client_msg::inspect_delete_payload(raw_payload);
            let action_label = match action {
                crate::client_msg::DeleteAction::Delete => "delete",
                crate::client_msg::DeleteAction::DeletePermanently => "delete-permanent",
                crate::client_msg::DeleteAction::Restore => "restore",
            };
            tracing::info!(
                "{prefix} DeleteEntry({action_label}): entry_id={entry_id} type={type_str} user={username} extra=[{extra}]"
            );

            match action {
                crate::client_msg::DeleteAction::Delete => {
                    match state.storage.move_to_trash(*entry_id as i32).await {
                        Ok(true) => tracing::info!("{prefix} Soft-deleted {type_str} entry_id={entry_id}"),
                        Ok(false) => tracing::debug!("{prefix} Delete {type_str} entry_id={entry_id}: not found, ignoring stale client state"),
                        Err(e) => { tracing::error!("{prefix} failed to delete {type_str}: {e}"); return None; }
                    }
                }
                crate::client_msg::DeleteAction::DeletePermanently => {
                    match state.storage.delete_from_trash(*entry_id as i32).await {
                        Ok(true) => tracing::info!("{prefix} Permanent-deleted {type_str} entry_id={entry_id}"),
                        Ok(false) => tracing::debug!("{prefix} Perm-delete {type_str} entry_id={entry_id}: not found, ignoring stale client state"),
                        Err(e) => { tracing::error!("{prefix} failed to perm-delete {type_str}: {e}"); return None; }
                    }
                }
                crate::client_msg::DeleteAction::Restore => {
                    match state.storage.restore_from_trash(*entry_id as i32).await {
                        Ok(true) => tracing::info!("{prefix} Restored {type_str} entry_id={entry_id}"),
                        Ok(false) => tracing::debug!("{prefix} Restore {type_str} entry_id={entry_id}: not found, ignoring stale client state"),
                        Err(e) => { tracing::error!("{prefix} failed to restore {type_str}: {e}"); return None; }
                    }
                }
            }

            None
        }

        ClientMsg::Unknown { msg_type, .. } => {
            if *msg_type == 7 {
                tracing::info!("{prefix} type7 received");
            }
            tracing::warn!("{prefix} Unknown message type {msg_type}");
            None
        }
    }
}

async fn save_type7_blob(
    state: &AppState,
    payload: &[u8],
    prefix: &str,
) -> anyhow::Result<()> {
    let blob = extract_type7_blob_text(payload)?;

    if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(blob.trim()) {
        if let Ok(value) = rmp_serde::from_slice::<serde_json::Value>(&raw) {
            let top_keys: Vec<&str> = value
                .as_object()
                .map(|m| m.keys().map(|k| k.as_str()).collect())
                .unwrap_or_default();
            tracing::info!(
                "{prefix} type7 blob: {} top-level keys: {:?}",
                blob.len(),
                top_keys
            );
            if let Ok(json) = serde_json::to_string(&value) {
                tracing::debug!("{prefix} type7 json: {}", json);
            }
        }
    }

    if let Some(selection) = decode_style_selection(&blob) {
        match selection {
            StyleSelection::BuiltIn { id, name } => {
                tracing::info!("{prefix} type7 selected style id={id} ({name})");
                if let Err(e) = state.storage.set_last_loaded_style(None).await {
                    tracing::error!("{prefix} failed to clear custom style selection: {e}");
                }
            }
            StyleSelection::Other(id) => {
                tracing::info!("{prefix} type7 selected style id={id} (custom/unknown)");
                match i32::try_from(id) {
                    Ok(entry_id) => {
                        if state.storage.entry_exists(entry_id).await {
                            if let Err(e) = state
                                .storage
                                .set_last_loaded_style(Some(entry_id))
                                .await
                            {
                                tracing::error!(
                                    "{prefix} failed to remember custom style selection: {e}"
                                );
                            }
                        } else {
                            tracing::warn!(
                                "{prefix} type7 selected custom style id={entry_id}, but no matching style file exists"
                            );
                        }
                    }
                    Err(_) => {
                        tracing::warn!("{prefix} type7 selected style id={id} out of range");
                    }
                }
            }
        }
    }

    state.storage.update_type7_blob(Some(&blob)).await?;
    Ok(())
}

enum StyleSelection {
    BuiltIn { id: i64, name: &'static str },
    Other(i64),
}

fn decode_style_selection(blob_b64: &str) -> Option<StyleSelection> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob_b64.trim())
        .ok()?;
    let value: serde_json::Value = rmp_serde::from_slice(&raw).ok()?;
    let selected = value
        .get(crate::config::STYLE_SELECTION_KEY_1)?
        .get(crate::config::STYLE_SELECTION_KEY_2)?
        .get(crate::config::STYLE_SELECTION_KEY_3)?
        .as_i64()?;

    match selected {
        0 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Blue",
        }),
        1 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Black",
        }),
        2 => Some(StyleSelection::BuiltIn {
            id: selected,
            name: "Light",
        }),
        _ => Some(StyleSelection::Other(selected)),
    }
}

fn extract_type7_blob_text(payload: &[u8]) -> anyhow::Result<String> {
    fn is_b64ish(b: u8) -> bool {
        matches!(b,
            b'A'..=b'Z' |
            b'a'..=b'z' |
            b'0'..=b'9' |
            b'+' | b'/' | b'=' |
            b'-' | b'_')
    }

    let mut best = (0usize, 0usize);
    let mut start = None;

    for (idx, &byte) in payload.iter().enumerate() {
        if is_b64ish(byte) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            let len = idx - s;
            if len > best.1 {
                best = (s, len);
            }
        }
    }

    if let Some(s) = start {
        let len = payload.len() - s;
        if len > best.1 {
            best = (s, len);
        }
    }

    anyhow::ensure!(best.1 > 32, "type7 blob text not found");
    let text = std::str::from_utf8(&payload[best.0..best.0 + best.1])
        .context("type7 blob candidate was not UTF-8")?
        .trim_matches('\0')
        .to_string();
    anyhow::ensure!(!text.is_empty(), "type7 blob text empty");
    Ok(text)
}

fn share_entry_type_name(entry_type: u32) -> &'static str {
    match entry_type {
        1 => "Config",
        2 => "Script",
        3 => "Style",
        _ => "Unknown",
    }
}

fn msg_summary(msg: &Message) -> String {
    match msg {
        Message::Text(t) => {
            let s = t.as_str();
            if s.len() > 200 {
                format!("text({}B): {}...", s.len(), &s[..200])
            } else {
                format!("text({}B): {s}", s.len())
            }
        }
        Message::Binary(b) => {
            let hex_preview: String = b
                .iter()
                .take(32)
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(" ");
            format!("binary({}B): {}", b.len(), hex_preview)
        }
        Message::Ping(b) => format!("ping({}B)", b.len()),
        Message::Pong(b) => format!("pong({}B)", b.len()),
        Message::Close(c) => format!("close({c:?})"),
    }
}
