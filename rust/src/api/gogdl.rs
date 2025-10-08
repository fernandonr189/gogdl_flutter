use flutter_rust_bridge::frb;
use gogdl_rs::{
    auth::auth::AuthError, session::session::SessionError, user::user::User, Auth, GamesDownloader,
    GogDbGameDetails, Session,
};

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

#[frb]
pub async fn gog_get_owned_games(user: &mut User) -> Result<Vec<u64>, SessionError> {
    let games = user.get_owned_games().await?;
    Ok(games)
}

#[frb]
pub async fn gog_get_game_details(
    downloader: &GamesDownloader,
    game_id: &str,
) -> Result<GogDbGameDetails, SessionError> {
    let game_details = downloader.get_game_details(game_id).await?;
    Ok(game_details)
}

#[frb(sync)]
pub fn gog_get_image_boxart(game_details: &GogDbGameDetails) -> Result<String, String> {
    game_details
        .image_boxart
        .clone()
        .ok_or("Image boxart not found".to_owned())
}
