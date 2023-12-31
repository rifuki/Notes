use std::env;

use actix_cors::Cors;
use actix_web::{
    get,
    middleware::{Logger, NormalizePath},
    web, App, HttpResponse, HttpServer,
};
use log::Level;
use simple_logger::init_with_level as LoggerWithLevel;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use notes_actix::{
    notes::{
        handler::{
            __path_create_note, __path_delete_note, __path_get_all_notes, __path_get_note,
            __path_update_note,
        },
        models::{Note, NoteBuilder, NoteJoinUser, NoteUpdatePayload},
        routes::scoped_notes,
    },
    ping::handler::{
        __path_increment_counter, __path_ping_service, __path_server_time, increment_counter,
        ping_service, server_time,
    },
    types::AppState,
    users::{
        admin::{__path_register_admin, register_admin},
        handler::{
            __path_auth_login, __path_auth_logout, __path_auth_refresh, __path_auth_register,
            __path_delete_user, __path_get_all_users, __path_get_user, __path_update_user,
            auth_login, auth_logout, auth_refresh, auth_register,
        },
        models::{
            AdminBuilder, User, UserClaims, UserLoginPayload, UserRegisterPayload,
            UserUpdatePayload,
        },
        routes::scoped_users,
    },
    utils::{establish_database_pool, initialize_redis_pool},
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let app_port = env::var("APP_PORT")
        .unwrap_or(String::from("80"))
        .parse::<u16>()
        .expect("Failed to parse APP_PORT");
    let db_url = env::var("DATABASE_URL").expect("Env DATABASE_URL must be set first.");
    let redis_port = env::var("REDIS_PORT").expect("Env REDIS_PORT is not set.");
    let redis_url = format!("redis://127.0.0.1:{}", redis_port);
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
        .expect("Failed to parse TOKEN_DURATION_REFRESH.");
    env::var("HTTPS")
        .unwrap_or(String::from("false"))
        .to_lowercase()
        .parse::<bool>()
        .unwrap();
    // End of Checking env variables for forward compatibility.
    let redis_pool = initialize_redis_pool(&redis_url).await;
    let db_pool = establish_database_pool(&db_url).await;
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .unwrap_or_else(|err| panic!("Error running DB migrations. {}", err));
    let app_state = AppState {
        db_pool,
        redis_pool,
    };

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
        paths(get_all_notes, create_note, get_note, update_note, delete_note, auth_login, auth_logout, auth_refresh, auth_register, get_all_users, get_user, update_user, delete_user, ping_service, register_admin, server_time, increment_counter),
        components(schemas(Note, NoteBuilder, NoteUpdatePayload, NoteJoinUser, User, UserClaims, UserLoginPayload, UserRegisterPayload, UserUpdatePayload, AdminBuilder)),
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

    LoggerWithLevel(Level::Info).unwrap();
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_header()
            .allow_any_method()
            .allow_any_origin();

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .service(
                SwaggerUi::new("/docs/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(index)
            .service(ping_service)
            .service(server_time)
            .service(increment_counter)
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
