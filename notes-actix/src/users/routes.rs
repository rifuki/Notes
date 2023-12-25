use actix_web::web;

use crate::users::handler::{delete_user, get_all_users, get_user, update_user};

pub fn scoped_users(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("", web::get().to(get_all_users))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::put().to(update_user))
            .route("/{id}", web::delete().to(delete_user)),
    );
}
