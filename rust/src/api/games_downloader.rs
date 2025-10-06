use crate::{
    api::{
        auth::Session,
        error::{AuthError, DownloaderError},
    },
    frb_generated::StreamSink,
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
    async fn generate_files_queue(
        &self,
        game_details: &GogDbGameDetails,
    ) -> Result<Vec<FileDownload>, DownloaderError> {
        let latest_build = game_details.get_latest_build()?;
        let manifest = self.get_build_manifest(latest_build).await?;
        let depots = self.get_depot_manifests(&manifest).await?;
        let mut download_chunks: Vec<FileDownload> = Vec::new();
        for depot in depots {
            for item in depot.items {
                if !item.path.is_none() && !item.chunks.is_none() && !item.depot_manifest.is_none()
                {
                    let download_file = FileDownload {
                        path: item.path.unwrap(),
                        chunks: item.chunks.unwrap(),
                        depot_manifest: item.depot_manifest.unwrap(),
                    };
                    download_chunks.push(download_file);
                }
            }
        }
        Ok(download_chunks)
    }
    async fn get_depot_manifests(
        &self,
        manifest: &GogDbBuildManifest,
    ) -> Result<Vec<DepotData>, DownloaderError> {
        let depot_manifest_hashes: Vec<String> =
            manifest.depots.iter().map(|s| s.manifest.clone()).collect();

        let depot_manifest_urls: Vec<String> = depot_manifest_hashes
            .iter()
            .map(|m| {
                let url = format!(
                    "https://cdn.gog.com/content-system/v2/meta/{}/{}/{}",
                    &m[0..2],
                    &m[2..4],
                    m
                );
                url
            })
            .collect();

        let mut depot_manifests = Vec::new();
        for (url, hash) in depot_manifest_urls.iter().zip(depot_manifest_hashes.iter()) {
            let mut resp: DepotManifest =
                match self.session.get_request_compressed(url.clone()).await {
                    Ok(resp) => resp,
                    Err(e) => return Err(DownloaderError::RequestError(e.to_string())),
                };
            resp.depot.set_id(hash.clone());
            depot_manifests.push(resp.depot);
        }

        Ok(depot_manifests)
    }
    async fn get_build_manifest(
        &self,
        build: GogDbGameBuild,
    ) -> Result<GogDbBuildManifest, DownloaderError> {
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
        Ok(manifest)
    }
    #[frb]
    pub async fn download_all_files_with_progress(
        &self,
        files: Vec<FileDownload>,
        sink: StreamSink<DownloadProgress>,
    ) -> Result<(), DownloaderError> {
        let session_clone = self.session.clone();
        tokio::spawn(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(10)); // 10 concurrent downloads
            let total_bytes: u64 = files
                .iter()
                .flat_map(|f| f.chunks.iter().filter_map(|c| c.size))
                .sum();

            let completed_bytes = Arc::new(tokio::sync::Mutex::new(0u64));

            let mut handles = Vec::new();

            for file in files {
                for chunk in file.clone().chunks {
                    let permit = semaphore.clone().acquire_owned().await.unwrap();
                    let completed_bytes = completed_bytes.clone();
                    let sink_clone = sink.clone();
                    let file_clone = file.clone();
                    let session_clone = session_clone.clone();

                    handles.push(tokio::spawn(async move {
                        // 1️⃣ download the chunk
                        if let Err(e) = session_clone.download_chunk(&file_clone, &chunk).await {
                            eprintln!("Chunk failed: {}", e);
                        }

                        // 2️⃣ update total progress
                        if let Some(size) = chunk.size {
                            let mut completed = completed_bytes.lock().await;
                            *completed += size;
                            let progress = (*completed as f64 / total_bytes as f64) * 100.0;
                            match sink_clone.add(DownloadProgress {
                                downloaded_bytes: *completed,
                                total_bytes: total_bytes,
                                percentage: progress,
                            }) {
                                Ok(_) => (),
                                Err(e) => eprintln!("Failed to send progress: {}", e),
                            }
                        }

                        drop(permit);
                    }));
                }
            }
            for h in handles {
                let _ = h.await;
            }
        });
        Ok(())
    }
}
#[frb]
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percentage: f64,
}
#[derive(Debug, Clone)]
pub struct FileDownload {
    pub path: String,
    pub chunks: Vec<DepotChunk>,
    pub depot_manifest: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DepotChunk {
    #[serde(rename = "compressedMd5")]
    pub compressed_md5: Option<String>,
    #[serde(rename = "compressedSize")]
    pub compressed_size: Option<u64>,
    pub md5: Option<String>,
    pub size: Option<u64>,
}

impl DepotChunk {
    pub fn is_valid(&self) -> bool {
        self.md5.is_some() || self.compressed_md5.is_some()
    }
}

#[frb(opaque)]
#[derive(Deserialize, Debug, Clone)]
pub struct DepotItem {
    pub chunks: Option<Vec<DepotChunk>>,
    pub md5: Option<String>,
    pub path: Option<String>,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
    pub depot_manifest: Option<String>,
}
impl DepotItem {
    pub fn set_depot_manifest(&mut self, depot_manifest: String) {
        self.depot_manifest = Some(depot_manifest);
    }
}

#[derive(Deserialize, Debug)]
pub struct DepotManifest {
    pub depot: DepotData,
    pub version: u64,
}

#[frb(opaque)]
#[derive(Deserialize, Debug, Clone)]
pub struct DepotData {
    pub items: Vec<DepotItem>,
    pub manifest_id: Option<String>,
}
impl DepotData {
    pub fn set_id(&mut self, id: String) {
        self.manifest_id = Some(id);
    }
}

#[derive(Deserialize, Debug)]
pub struct GogDbBuildManifest {
    pub dependencies: Option<Vec<String>>,
    pub depots: Vec<Depot>,
}

#[derive(Deserialize, Debug)]
pub struct Depot {
    #[serde(rename = "compressedSize")]
    pub compressed_size: u64,
    pub manifest: String,
    pub size: u64,
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
