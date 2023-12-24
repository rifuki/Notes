use actix_web::web;

use crate::notes::handler::{create_note, delete_note, get_all_notes, get_note, update_note};

pub fn scoped_notes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/notes")
            .route("", web::get().to(get_all_notes))
            .route("", web::post().to(create_note))
            .route("/{id}", web::get().to(get_note))
            .route("/{id}", web::put().to(update_note))
            .route("/{id}", web::delete().to(delete_note)),
    );
}
