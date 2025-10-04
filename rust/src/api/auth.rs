use std::sync::{Arc, Mutex};

use flutter_rust_bridge::frb;
use serde::Deserialize;

pub const GOG_AUTH_URL: &str = "https://auth.gog.com";
pub const GOG_CLIENT_ID: &str = "46899977096215655";
pub const GOG_CLIENT_SECRET: &str =
    "9d85c43b1482497dbbce61f6e4aa173a433796eeae2ca8c5f6129f2dc4de46d9";
pub const GOG_REDIRECT_URI: &str = "https://embed.gog.com/on_login_success?origin=client";
pub const GOG_RESPONSE_TYPE: &str = "code";
pub const GOG_LAYOUT: &str = "client2";
pub const GOG_GRANT_TYPE: &str = "authorization_code";

pub struct Auth {
    pub session_code: Option<String>,
    pub gog_token: Option<GogTokenResponse>,
}

#[frb(opaque)]
pub struct Session {
    pub auth: Arc<Mutex<Auth>>,
}

impl Session {
    #[frb(sync)]
    pub fn open_browser(&self) -> Result<(), std::io::Error> {
        let mut url = url::Url::parse(&format!("{}/auth", GOG_AUTH_URL)).unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", GOG_CLIENT_ID);
        url.query_pairs_mut()
            .append_pair("client_secret", GOG_CLIENT_SECRET);
        url.query_pairs_mut()
            .append_pair("redirect_uri", GOG_REDIRECT_URI);
        url.query_pairs_mut()
            .append_pair("response_type", GOG_RESPONSE_TYPE);
        url.query_pairs_mut().append_pair("layout", GOG_LAYOUT);
        open::that(url.as_str())
    }
    #[frb(sync)]
    pub fn new() -> Self {
        Self {
            auth: Arc::new(Mutex::new(Auth {
                session_code: None,
                gog_token: None,
            })),
        }
    }
    #[frb(sync)]
    pub fn set_session_code(&self, session_code: String) {
        let mut auth = self.auth.lock().unwrap();
        auth.session_code = Some(session_code);
    }
    #[frb(sync)]
    pub fn login(&self) -> Result<(), reqwest::Error> {
        let mut auth = self.auth.lock().unwrap();
        let mut url = url::Url::parse(&format!("{}/token", GOG_AUTH_URL)).unwrap();
        let code = auth.session_code.clone().unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", GOG_CLIENT_ID);
        url.query_pairs_mut()
            .append_pair("client_secret", GOG_CLIENT_SECRET);
        url.query_pairs_mut()
            .append_pair("grant_type", GOG_GRANT_TYPE);
        url.query_pairs_mut().append_pair("code", &code);
        url.query_pairs_mut()
            .append_pair("redirect_uri", GOG_REDIRECT_URI);
        let resp = reqwest::blocking::get(url);
        let json = match resp {
            Ok(res) => res.json::<GogTokenResponse>().unwrap(),
            Err(err) => return Err(err),
        };
        auth.gog_token = Some(json.clone());
        println!("Logged in successfully!: {:?}", json);
        Ok(())
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
