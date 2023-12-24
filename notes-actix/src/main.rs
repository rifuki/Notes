use actix_web::{get, middleware::NormalizePath, web, App, HttpResponse, HttpServer};
use notes_actix::{
    notes::{
        handler::{
            __path_create_note, __path_delete_note, __path_get_all_notes, __path_get_note,
            __path_update_note,
        },
        models::{Notes, NotesBuilder},
        routes::scoped_notes,
    },
    ping::handler::ping_service,
    types::AppState,
    users::routes::scoped_users,
    utils::establish_connection,
};
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let current_dir = env::current_dir().unwrap();
    let parent_dir = current_dir.parent().unwrap();
    let parent_env_path = parent_dir.join(".env");
    dotenv::from_path(parent_env_path).ok();

    let app_port = env::var("APP_PORT")
        .unwrap_or(String::from("80"))
        .parse::<u16>()
        .expect("Failed to parse APP_PORT");

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set first.");
    let db_pool = establish_connection(&db_url);
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Error running DB migrations");

    let app_state = AppState { db_pool };

    #[derive(OpenApi)]
    #[openapi(
        info(title = "Notes API", version = "0.1.0"),
        components(schemas(Notes, NotesBuilder)),
        paths(get_all_notes, create_note, get_note, update_note, delete_note)
    )]
    struct ApiDoc;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .service(
                SwaggerUi::new("/docs/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(index)
            .service(ping_service)
            .service(
                web::scope("/api").wrap(NormalizePath::trim()).service(
                    web::scope("/v1")
                        .configure(scoped_notes)
                        .configure(scoped_users),
                ),
            )
    })
    .bind(("::", app_port))?
    .run()
    .await
}

#[get("/")]
async fn index() -> HttpResponse {
    HttpResponse::Found()
        .insert_header(("location", "/docs/"))
        .finish()
}
