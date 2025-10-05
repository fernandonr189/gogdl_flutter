use crate::api::{
    auth::Session,
    error::{AuthError, DownloaderError},
};
use chrono::{DateTime, FixedOffset};
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
    #[frb]
    pub async fn download_game(
        &self,
        game_details: GogDbGameDetails,
    ) -> Result<(), DownloaderError> {
        let latest_build = game_details.get_latest_build()?;
        self.get_build_manifest(latest_build).await?;
        Ok(())
    }
    async fn get_build_manifest(&self, build: GogDbGameBuild) -> Result<(), DownloaderError> {
        let link = {
            if let Some(link) = build.link {
                link
            } else {
                return Err(DownloaderError::MissingManifestUrl);
            }
        };

        let manifest: GogDbBuildManifest = match self.session.get_request_compressed(link).await {
            Ok(manifest) => manifest,
            Err(err) => return Err(DownloaderError::RequestError(err.to_string())),
        };
        println!("Obtained build manifest: {:?}", manifest);
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
pub struct GogDbBuildManifest {
    pub dependencies: Vec<String>,
    pub depots: Vec<Depot>,
}

#[derive(Deserialize, Debug)]
pub struct Depot {
    #[serde(rename = "compressedSize")]
    pub compressed_size: i32,
    pub manifest: String,
    pub size: i32,
}

#[derive(Deserialize, Debug)]
pub struct GogDbGameDetails {
    pub title: Option<String>,
    pub image_boxart: Option<String>,
    #[serde(rename = "type")]
    pub product_type: Option<String>,
    pub builds: Vec<GogDbGameBuild>,
}

impl GogDbGameDetails {
    pub fn get_latest_build(&self) -> Result<GogDbGameBuild, DownloaderError> {
        let builds_with_dates: Vec<(&GogDbGameBuild, DateTime<FixedOffset>)> = self
            .builds
            .iter()
            .map(|b| {
                let dt = b
                    .date_published
                    .as_ref()
                    .and_then(|s| s.parse::<DateTime<FixedOffset>>().ok())
                    .unwrap_or_default();
                (b, dt)
            })
            .collect();

        if let Some((latest_build, _)) = builds_with_dates.iter().max_by_key(|(_, dt)| *dt) {
            Ok((*latest_build).clone())
        } else {
            Err(DownloaderError::GetLatestBuildError(
                "Could not obtain latest build".to_string(),
            ))
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct OwnedGamesResponse {
    pub owned: Vec<u64>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GogDbGameBuild {
    pub date_published: Option<String>,
    pub link: Option<String>,
}
