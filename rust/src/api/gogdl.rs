use flutter_rust_bridge::frb;
use gogdl_rs::{
    auth::auth::AuthError, games::games_downloader::GameBuild, session::session::SessionError,
    user::user::User, Auth, GamesDownloader, GogDbGameDetails, Session,
};

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
