#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::form::{self, Form, Error};

#[derive(FromForm, Debug)]
struct User<'r> {
    #[field(validate = authuser(&self.password))]
    ssn: u64,
    password: &'r str,
}

#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
fn userlogon(user: Form<User<'_>>) -> Template{
    println!("{:?}",user);
    Template::render("authgood",context!{})
}

fn authuser<'v>(ssn: &u64, password: &str) -> form::Result<'v, ()>{
    // do database stuff
    println!("SSN: {}, Password: {}",ssn,password);
    match password{
        "1234" => Ok(()),
        _ => Err(Error::validation("Bad password"))?,
    }
}

#[catch(422)]
fn invalid() -> Template {
    Template::render("authfail",context! {})
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, userlogon]).register("/", catchers![invalid])
    .attach(Template::fairing())
}
