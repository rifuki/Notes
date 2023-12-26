use std::env;

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
    ping::handler::{__path_ping_service, ping_service},
    types::AppState,
    users::{
        handler::{
            __path_auth_login, __path_auth_logout, __path_auth_refresh, __path_auth_register,
            __path_delete_user, __path_get_all_users, __path_get_user, __path_update_user,
            auth_login, auth_logout, auth_refresh, auth_register,
        },
        models::{User, UserClaims, UserLoginPayload, UserRegisterPayload, UserUpdatePayload},
        routes::scoped_users, admin::register_admin,
    },
    utils::establish_connection,
};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
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
    let db_url = env::var("DATABASE_URL").expect("Env DATABASE_URL must be set first.");

    // Checking env variables for forward compatibility.
    env::var("SECRET_KEY_ACCESS").unwrap_or_else(|_| panic!("Env SECRET_KEY_ACCESS is not set."));
    env::var("SECRET_KEY_REFRESH").unwrap_or_else(|_| panic!("Env SECRET_KEY_REFRESH is not set."));
    env::var("TOKEN_DURATION_ACCESS")
        .unwrap_or_else(|_| panic!("Env TOKEN_DURATION_ACCESS is not set."))
        .parse::<i64>()
        .expect("Failed to parse TOKEN_DURATION_ACCESS.");
    env::var("TOKEN_DURATION_REFRESH")
        .unwrap_or_else(|_| panic!("Env TOKEN_DURATION_REFRESH is not set."))
        .parse::<i64>()
        .expect("Failed to parse TOKEN_DURATION_ACCESS.");
    // End of Checking env variables for forward compatibility.

    let db_pool = establish_connection(&db_url);
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Error running DB migrations");
    let app_state = AppState { db_pool };

    #[derive(OpenApi)]
    #[openapi(
        info(
            title = "Notes API",
            version = "0.1.0",
            description = "This API provides endpoints to manage notes and user authentication.",
            contact(
                name = "rifuki",
                email = "mahomarifuki@gmail.com",
                url = "https://rifuki.codes"
            ),
            license(
                name = "MIT License",
                url = "https://opensource.org/licenses/MIT"
            )
        ),
        paths(get_all_notes, create_note, get_note, update_note, delete_note, auth_login, auth_logout, auth_refresh, auth_register, get_all_users, get_user, update_user, delete_user, ping_service),
        components(schemas(Notes, NotesBuilder, User, UserClaims, UserLoginPayload, UserRegisterPayload, UserUpdatePayload)),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;
    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().unwrap();
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }

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
                        .route("/login", web::post().to(auth_login))
                        .route("/register", web::post().to(auth_register))
                        .route("/logout", web::get().to(auth_logout))
                        .route("/refresh", web::get().to(auth_refresh))
                        .route("/admin/register", web::post().to(register_admin))
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
