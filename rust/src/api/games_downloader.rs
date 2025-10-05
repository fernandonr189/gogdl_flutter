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
        let resp: GogDbGameDetails = self.session.get_request(url).await?;
        Ok(resp)
    }
}

#[derive(Deserialize, Debug)]
pub struct GogDbGameDetails {
    pub title: Option<String>,
    pub image_boxart: Option<String>,
    #[serde(rename = "type")]
    pub product_type: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct OwnedGamesResponse {
    pub owned: Vec<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct GameDetailsResponse {
    pub title: Option<String>,
    #[serde(rename = "backgroundImage")]
    pub background_image: Option<String>,
    pub cd_key: Option<String>,
    pub text_information: Option<String>,
    pub downloads: Vec<(String, DownloadsByLanguage)>,
    #[serde(rename = "galaxyDownloads")]
    pub galaxy_downloads: Vec<DownloadPlatform>,
    pub extras: Vec<ExtraFile>,
    pub dlcs: Vec<Dlc>,
    pub tags: Vec<String>,
    pub is_preorder: Option<bool>,
    pub release_timestamp: Option<i64>,
    pub messages: Vec<String>,
    pub changelog: Option<String>,
    pub forum_link: Option<String>,
    pub is_base_product_missing: Option<bool>,
    pub missing_base_product: Option<String>,
    pub features: Vec<String>,
    #[serde(rename = "simpleGalaxyInstallers")]
    pub simple_galaxy_installers: Vec<SimpleGalaxyInstaller>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct DownloadsByLanguage {
    pub windows: Vec<DownloadFile>,
    pub mac: Vec<DownloadFile>,
    pub linux: Vec<DownloadFile>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct DownloadFile {
    #[serde(rename = "manualUrl")]
    pub manual_url: Option<String>,
    #[serde(rename = "downloaderUrl")]
    pub downloader_url: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub date: Option<String>,
    pub size: Option<String>,
    pub os: Option<String>, // optional platform info if present
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ExtraFile {
    #[serde(rename = "manualUrl")]
    pub manual_url: Option<String>,
    #[serde(rename = "downloaderUrl")]
    pub downloader_url: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
    pub info: Option<u32>,
    pub size: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Dlc {
    pub id: Option<u64>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct SimpleGalaxyInstaller {
    pub path: Option<String>,
    pub os: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct DownloadPlatform {
    #[serde(rename = "manualUrl")]
    pub manual_url: Option<String>,
    #[serde(rename = "downloaderUrl")]
    pub downloader_url: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub date: Option<String>,
    pub size: Option<String>,
    pub os: Option<String>,
}
