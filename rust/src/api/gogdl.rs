use std::sync::Arc;

use flutter_rust_bridge::frb;
use gogdl_rs::{
    auth::auth::AuthError, games::games_downloader::GameBuild, session::session::SessionError,
    user::user::User, Auth, GamesDownloader, GogDbGameDetails, Session,
};
use tokio::sync::Semaphore;

use crate::frb_generated::StreamSink;

#[frb(sync)]
pub fn gog_initialize() -> Session {
    let session = Session::new();
    session
}

#[frb(sync)]
pub fn gog_get_auth(session: &Session) -> Auth {
    let auth = Auth::new(session);
    auth
}

#[frb]
pub async fn gog_get_downloader(
    session: &Session,
    auth: &Auth,
) -> Result<GamesDownloader, AuthError> {
    let token = auth.get_token().await?;
    let downloader = GamesDownloader::new(session, &token);
    Ok(downloader)
}
#[frb]
pub async fn gog_get_user(session: &Session, auth: &Auth) -> Result<User, AuthError> {
    let token = auth.get_token().await?;
    let user = User::new(session, &token);
    Ok(user)
}

#[frb]
pub async fn gog_login(auth: &mut Auth, session_code: &str) -> Result<(), SessionError> {
    auth.login(session_code).await
}
pub async fn gog_get_owned_games(
    user: &mut User,
    downloader: &GamesDownloader,
    sink: StreamSink<Vec<GogDbGameDetails>>,
) -> anyhow::Result<()> {
    let games = user.get_owned_games().await?;

    let mut game_details = Vec::new();
    for &game_id in &games {
        let mut details = match gog_get_game_details(downloader, game_id).await {
            Ok(details) => details,
            Err(_) => continue,
        };
        if details.product_type == Some("game".to_owned()) {
            details.set_id(game_id);
            game_details.push(details);
            match sink.add(game_details.clone()) {
                Ok(_) => (),
                Err(_e) => continue,
            }
        }
    }
    Ok(())
}
#[frb(sync)]
pub fn gog_get_game_id(game_details: &GogDbGameDetails) -> u64 {
    game_details.game_id.unwrap_or_default()
}

#[frb]
pub async fn gog_get_game_details(
    downloader: &GamesDownloader,
    game_id: u64,
) -> Result<GogDbGameDetails, SessionError> {
    let game_details = downloader.get_game_details(game_id).await?;
    Ok(game_details)
}
pub async fn download_build(
    downloader: &GamesDownloader,
    game_details: &GogDbGameDetails,
    build_link: &str,
    sink: StreamSink<DownloadProgress>,
) -> Result<(), SessionError> {
    let mut secure_links_response = downloader
        .get_secure_links(game_details.game_id.unwrap_or_default())
        .await?;
    secure_links_response.urls.sort_by_key(|cdn| cdn.priority);
    secure_links_response.urls.reverse();

    let build_metadata = downloader.get_build_metadata(build_link).await?;
    let depots = {
        let mut depots = Vec::new();
        for depot in build_metadata.depots {
            depots.push(downloader.get_depot_information(&depot).await?);
        }
        depots
    };

    let mut files = {
        let mut files = Vec::new();
        for depot in depots {
            for mut file in depot.depot.items {
                if file.file_type == "DepotFile".to_owned() {
                    file.set_is_gog_depot(depot.is_gog_depot.unwrap_or(false));
                    files.push(file);
                }
            }
        }
        files
    };

    for file in &mut files {
        if file.chunks.clone().unwrap_or_default().len() > 1 {
            file.chunks
                .clone()
                .unwrap_or_default()
                .iter_mut()
                .enumerate()
                .for_each(|(index, chunk)| {
                    chunk.set_order(index as i32);
                });
        }
    }

    let size = files.iter().map(|file| file.get_size()).sum::<u64>();
    println!("Total size: {} bytes", size);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let max_concurrent_downloads = 6; // adjust as needed
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads));

    for file in &files {
        for chunk in file.chunks.clone().unwrap_or_default().clone() {
            let current_chunk = chunk.clone();
            let secure_links_clone = secure_links_response.clone();
            let downloader_clone = downloader.clone();
            let tx_clone = tx.clone();
            let sem_clone = semaphore.clone();
            let is_gog_depot = file.is_gog_depot.unwrap_or(false);

            tokio::spawn(async move {
                // Acquire a permit before starting the download
                let _permit = sem_clone.acquire_owned().await.unwrap();

                if let Err(e) = downloader_clone
                    .download_chunk(
                        &secure_links_clone.urls,
                        &current_chunk.compressed_md5,
                        tx_clone,
                        is_gog_depot,
                    )
                    .await
                {
                    eprintln!("Chunk download failed: {:?}", e);
                }

                // Permit is automatically released when `_permit` goes out of scope
            });
        }
    }

    let mut progress = 0;
    while let Some(new_progress) = rx.recv().await {
        progress += new_progress;
        sink.add(DownloadProgress {
            game_name: game_details.title.clone().unwrap_or("Unknown".to_owned()),
            total_bytes: size,
            download_progress: progress as u64,
            is_complete: progress as u64 == size,
        })
        .unwrap();
    }
    Ok(())
}

#[frb]
pub async fn gog_get_game_builds(
    downloader: &GamesDownloader,
    game_id: u64,
) -> Result<Vec<GameBuild>, SessionError> {
    let builds = downloader.get_builds_data(game_id).await?;
    Ok(builds.items)
}
#[frb(sync)]
pub fn gog_get_build_name(build: &GameBuild) -> String {
    build.version_name.clone()
}

#[frb(sync)]
pub fn gog_get_build_date(build: &GameBuild) -> String {
    let date = build.get_date().unwrap();
    date.format("%Y-%m-%d").to_string()
}
#[frb(sync)]
pub fn gog_get_build_link(build: &GameBuild) -> String {
    build.link.clone()
}

#[frb(sync)]
pub fn gog_get_image_boxart(game_details: &GogDbGameDetails) -> Result<String, String> {
    let image_url = match game_details.image_boxart.clone() {
        Some(url) => url,
        None => return Err("Image boxart not found".to_owned()),
    };
    return Ok(format!("https://images.gog-statics.com/{}.jpg", image_url));
}

#[frb(sync)]
pub fn gog_get_game_title(game_details: &GogDbGameDetails) -> String {
    game_details.title.clone().unwrap()
}

#[frb(sync)]
pub fn gog_get_game_type(game_details: &GogDbGameDetails) -> String {
    game_details.product_type.clone().unwrap()
}

pub struct DownloadProgress {
    pub game_name: String,
    pub total_bytes: u64,
    pub download_progress: u64,
    pub is_complete: bool,
}
