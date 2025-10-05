use crate::api::{auth::Session, error::AuthError};
use flutter_rust_bridge::frb;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct GamesDownloader {
    pub session: Arc<Session>, // store an Arc<Session>
}

impl GamesDownloader {
    #[frb(sync)]
    pub fn new(session: Session) -> Self {
        let s = Arc::new(session);
        Self { session: s }
    }

    #[frb]
    pub async fn fetch_owned_game_ids(&self) -> Result<Vec<u64>, AuthError> {
        let url = "https://embed.gog.com/user/data/games".to_string();
        let resp: OwnedGamesResponse = self.session.get_request(url).await?;
        Ok(resp.owned)
    }
    #[frb]
    pub async fn fetch_game_details(&self, game_id: String) -> Result<GogDbGameDetails, AuthError> {
        let url = format!(
            "https://www.gogdb.org/data/products/{}/product.json",
            game_id
        );
        let resp: GogDbGameDetails = self.session.get_request_unauthorized(url).await?;
        Ok(resp)
    }
}

#[derive(Deserialize, Debug)]
pub struct GogDbGameDetails {
    pub title: Option<String>,
    pub image_boxart: Option<String>,
    #[serde(rename = "type")]
    pub product_type: Option<String>,
    pub builds: Vec<GogDbGameBuild>,
}

#[derive(Deserialize, Debug)]
pub struct OwnedGamesResponse {
    pub owned: Vec<u64>,
}

#[derive(Deserialize, Debug)]
pub struct GogDbGameBuild {
    pub date_published: Option<String>,
    pub generation: Option<i32>,
    pub link: Option<String>,
}
