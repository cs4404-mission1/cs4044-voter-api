#[macro_use] extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "<!DOCTYPE html><body> <h1>Hello, world!</h1></body>"
}




#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
    //.attach(Template::fairing())
}
