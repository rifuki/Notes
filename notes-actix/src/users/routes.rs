use actix_web::web;

use crate::users::handler::{
    auth_login, auth_register, delete_user, get_all_users, get_user, update_user,
};

pub fn scoped_users(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/login", web::post().to(auth_login))
            .route("/register", web::post().to(auth_register))
            .route("", web::get().to(get_all_users))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::put().to(update_user))
            .route("/{id}", web::delete().to(delete_user)),
    );
}
