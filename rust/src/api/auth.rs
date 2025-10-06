use std::{io::Read, sync::Arc, time::Duration};

use flate2::read::ZlibDecoder;
use flutter_rust_bridge::frb;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::api::error::AuthError;

pub const GOG_AUTH_URL: &str = "https://auth.gog.com";
pub const GOG_CLIENT_ID: &str = "46899977096215655";
pub const GOG_CLIENT_SECRET: &str =
    "9d85c43b1482497dbbce61f6e4aa173a433796eeae2ca8c5f6129f2dc4de46d9";
pub const GOG_REDIRECT_URI: &str = "https://embed.gog.com/on_login_success?origin=client";
pub const GOG_RESPONSE_TYPE: &str = "code";
pub const GOG_LAYOUT: &str = "client2";
pub const GOG_AUTH_GRANT_TYPE: &str = "authorization_code";
pub const GOG_REFRESH_GRANT_TYPE: &str = "refresh_token";

pub struct Auth {
    pub session_code: Option<String>,
    pub gog_token: Option<GogTokenResponse>,
}

#[frb(opaque)]
#[derive(Clone)]
pub struct Session {
    pub auth: Arc<Mutex<Auth>>,
    pub client: reqwest::Client,
}

impl Session {
    #[frb(sync)]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("GogDownloader/1.0")
            .build()
            .expect("Failed to build reqwest client");
        Self {
            auth: Arc::new(Mutex::new(Auth {
                session_code: None,
                gog_token: None,
            })),
            client,
        }
    }
    #[frb]
    pub async fn set_session_code(&self, session_code: String) {
        let mut auth = self.auth.lock().await;
        auth.session_code = Some(session_code);
    }
    #[frb]
    pub async fn login(&self) -> Result<(), AuthError> {
        let code_opt = {
            let auth = self.auth.lock().await;
            auth.session_code.clone()
        };
        let Some(code) = code_opt else {
            panic!("Attempted to login withtout session code")
        };
        let mut url = match url::Url::parse(&format!("{}/token", GOG_AUTH_URL)) {
            Ok(url) => url,
            Err(err) => return Err(AuthError::UrlError(err.to_string())),
        };
        url.query_pairs_mut()
            .append_pair("client_id", GOG_CLIENT_ID);
        url.query_pairs_mut()
            .append_pair("client_secret", GOG_CLIENT_SECRET);
        url.query_pairs_mut()
            .append_pair("grant_type", GOG_AUTH_GRANT_TYPE);
        url.query_pairs_mut().append_pair("code", &code);
        url.query_pairs_mut()
            .append_pair("redirect_uri", GOG_REDIRECT_URI);
        let resp = self.client.get(url).send().await;
        let json = match resp {
            Ok(res) => {
                if res.status().as_u16() != 200 {
                    return Err(AuthError::Auth(format!(
                        "Request failed with status: {}",
                        res.status().as_str()
                    )));
                }
                match res.json::<GogTokenResponse>().await {
                    Ok(res) => res,
                    Err(err) => return Err(AuthError::InvalidResponse(err.to_string())),
                }
            }
            Err(err) => return Err(AuthError::Network(err.to_string())),
        };
        println!("Logged in successfully!");
        {
            let mut auth = self.auth.lock().await;
            auth.gog_token = Some(json.clone());
        };
        let this = self.clone();
        tokio::spawn(async move {
            this.token_refresh_task(json.expires_in - 5).await;
        });
        Ok(())
    }
    pub async fn get_request_unauthorized<T>(&self, query: String) -> Result<T, AuthError>
    where
        T: serde::de::DeserializeOwned,
    {
        let result = self.client.get(query).send().await;
        match result {
            Ok(res) => {
                if res.status().as_u16() != 200 {
                    Err(AuthError::Network(format!(
                        "Request failed with status {}",
                        res.status().as_str()
                    )))
                } else {
                    match res.json::<T>().await {
                        Ok(t) => Ok(t),
                        Err(err) => Err(AuthError::InvalidResponse(err.to_string())),
                    }
                }
            }
            Err(err) => Err(AuthError::Network(err.to_string())),
        }
    }

    pub async fn get_request_compressed<T>(&self, query: String) -> Result<T, AuthError>
    where
        T: serde::de::DeserializeOwned,
    {
        let token = {
            let auth = self.auth.lock().await.gog_token.clone();
            if let Some(token) = auth {
                token.access_token
            } else {
                return Err(AuthError::Auth("No auth token".to_owned()));
            }
        };
        let result = self
            .client
            .get(query)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;
        match result {
            Ok(res) => {
                let bytes = if let Ok(bytes) = res.bytes().await {
                    bytes
                } else {
                    return Err(AuthError::Network("Failed to read response".to_owned()));
                };
                let mut d = ZlibDecoder::new(&bytes[..]);
                let mut s = String::new();
                d.read_to_string(&mut s).unwrap();
                println!("Decoded JSON:\n\n{}", s);
                match serde_json::from_str::<T>(&s) {
                    Ok(data) => Ok(data),
                    Err(err) => Err(AuthError::Network(err.to_string())),
                }
            }
            Err(err) => Err(AuthError::Network(err.to_string())),
        }
    }
    pub async fn get_request<T>(&self, query: String) -> Result<T, AuthError>
    where
        T: serde::de::DeserializeOwned,
    {
        let token = {
            let auth = self.auth.lock().await.gog_token.clone();
            if let Some(token) = auth {
                token.access_token
            } else {
                return Err(AuthError::Auth("No auth token".to_owned()));
            }
        };
        let result = self
            .client
            .get(query)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;
        match result {
            Ok(res) => {
                if res.status().as_u16() != 200 {
                    Err(AuthError::Network(format!(
                        "Request failed with status {}",
                        res.status().as_str()
                    )))
                } else {
                    match res.json::<T>().await {
                        Ok(t) => Ok(t),
                        Err(err) => Err(AuthError::InvalidResponse(err.to_string())),
                    }
                }
            }
            Err(err) => Err(AuthError::Network(err.to_string())),
        }
    }
    async fn token_refresh_task(&self, interval: i64) {
        loop {
            tokio::time::sleep(Duration::from_secs(interval as u64)).await;

            let refresh_token = {
                let auth = self.auth.lock().await;
                match auth.gog_token.clone() {
                    Some(token) => token.refresh_token,
                    None => {
                        println!("Cant refresh session, refresh token not found");
                        return;
                    }
                }
            };
            let mut url = match url::Url::parse(&format!("{}/token", GOG_AUTH_URL)) {
                Ok(url) => url,
                Err(err) => {
                    panic!("Could not parse url: {}", err);
                }
            };
            url.query_pairs_mut()
                .append_pair("client_id", GOG_CLIENT_ID);
            url.query_pairs_mut()
                .append_pair("client_secret", GOG_CLIENT_SECRET);
            url.query_pairs_mut()
                .append_pair("grant_type", GOG_REFRESH_GRANT_TYPE);
            url.query_pairs_mut()
                .append_pair("refresh_token", &refresh_token);
            let resp = self.client.get(url).send().await;
            match resp {
                Ok(res) => {
                    let gog_token = match res.json::<GogTokenResponse>().await {
                        Ok(token) => token,
                        Err(err) => {
                            println!("Could not parse token: {}", err);
                            continue;
                        }
                    };
                    let mut auth = self.auth.lock().await;
                    auth.gog_token = Some(gog_token);
                }
                Err(err) => {
                    println!("Could not refresh token: {}", err);
                }
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct GogTokenResponse {
    pub expires_in: i64,
    pub scope: String,
    pub token_type: String,
    pub access_token: String,
    pub user_id: String,
    pub refresh_token: String,
    pub session_id: String,
}
