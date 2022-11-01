#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::{form::{self, Form}, http::{Cookie, CookieJar}, State};
use rand_core::{RngCore, OsRng};
#[derive(FromForm, Debug)]
struct User<'r> {
    ssn: u64,
    password: &'r str,
}
// TODO: note for tomorrow: make a thread that hosts valid token vector in memory,
// then make stateful channel to communicate with it to add and remove entries.
#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
fn userlogon(state: &State<Persist>, cookies: &CookieJar<'_>, user: Form<User<'_>>) -> Template{
    println!("{:?}",&user);
    let authok = true;
    if authok{
        let rndm = OsRng.next_u32().to_string();
        cookies.add_private(Cookie::new("votertoken", rndm));
        // REMOVE ME state.valid_tokens.push(rndm);
    }
    Template::render("auth",context!{authok})
}

#[get("/vote")]
fn vote() -> Template {
    Template::render("index",context! {})
}


#[catch(422)]
fn invalid() -> Template {
    Template::render("invalid",context! {})
}

struct Persist {
    valid_tokens: Vec<String>,
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, userlogon])
    .register("/", catchers![invalid])
    .manage(Persist {valid_tokens: vec!()})
    .attach(Template::fairing())
}
