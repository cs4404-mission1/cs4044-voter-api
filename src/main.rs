#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::{form::Form, http::{Cookie, CookieJar}, State, response::Redirect};
use std::{thread, time::Duration};
use crossbeam::channel::{self, unbounded};
use std::sync::atomic::{AtomicUsize, Ordering};
use argon2::{password_hash::PasswordHasher,Argon2};
use rocket_db_pools::{sqlx::{self,Row}, Database, Connection};

#[derive(FromForm, Debug)]
struct User<'r> {
    ssn: u32,
    password: &'r str,
}

#[derive(FromForm, Debug)]
struct Ballot<'r> {
    candidate: &'r str,
}
// Database of Valid SSNs and Passwords
#[derive(Database)]
#[database("Vote")]
struct Vote(sqlx::SqlitePool);

struct Persist {
    rktsnd: channel::Sender<(u8, String)>,
    rktrcv: channel::Receiver<(u8, String)>,
    votekey: AtomicUsize,
}

#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
async fn userlogon(db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, user: Form<User<'_>>) -> Redirect{
    let authok: bool;
    match hash_password(user.password.to_string()){
        Ok(hash) => {
            match get_password(db, user.ssn).await{
                Some(tmp) => authok = hash == tmp,
                None => authok = false,
            }
            },
        Err(_) => return Redirect::to(uri!(index())),
    }
    if authok{
        println!("authentication OK");
        let rndm: String = (state.votekey.fetch_add(1, Ordering::Relaxed) + 1).to_string();
        cookies.add_private(Cookie::new("votertoken", rndm.clone()));
        state.rktsnd.send((1, rndm)).unwrap();
        return Redirect::to(uri!(vote()));
    }
    Redirect::to(uri!(index()))
}

#[get("/vote")]
fn vote(state: &State<Persist>, cookies: &CookieJar<'_>) -> Template {
    let mut status = 1;
    match cookies.get_private("votertoken"){
        Some(crumb) => {
            let key = crumb.value().to_string();
            state.rktsnd.send((0, key.clone())).unwrap();
            loop{
                let out = state.rktrcv.recv_timeout(Duration::from_millis(10)).unwrap();
                if out.1 == key{
                    status = out.0;
                    break; // possibility for lockup if token thread fails; let's not worry about that right now
                }
            }
        }
        None => return Template::render("auth",context!{authok: false}),
    }
    if status == 2 {panic!("Critical error in token store");}
    Template::render("vote",context! {status})
}

#[post("/vote", data = "<vote>")]
async fn recordvote(mut db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, vote: Form<Ballot<'_>>) -> Template{
    let mut status = 1;
    let key: String;
    match cookies.get_private("votertoken"){
        Some(crumb) => {
            key = crumb.value().to_string();
            println!("Vote: Got cookie with key {}", &key);
            state.rktsnd.send((0, key.clone())).unwrap();
            loop{
                let out = state.rktrcv.recv_timeout(Duration::from_millis(10)).unwrap();
                if out.1 == key{
                    status = out.0;
                    break; // possibility for lockup if token thread fails; let's not worry about that right now
                }
            }
            cookies.remove_private(crumb);
        }
        None => return Template::render("done",context!{}),
    }
    if status == 0{
        sqlx::query("INSERT INTO Votes VALUES (?)").bind(vote.candidate).execute(&mut *db).await.unwrap();
        println!("Key {} voted for {}",&key,vote.candidate);
        state.rktsnd.send((2, key)).unwrap();
    }
    Template::render("done",context!{})
    
}

#[get("/results")]
async fn show_results(mut db: Connection<Vote>) -> Template{
    let c1: u32 = sqlx::query("SELECT count(*) FROM Votes WHERE name = 'candidate1'").fetch_one(&mut *db).await.unwrap().get(0);
    let c2: u32 = sqlx::query("SELECT count(*) FROM Votes WHERE name = 'candidate2'").fetch_one(&mut *db).await.unwrap().get(0);
    let c3: u32 = sqlx::query("SELECT count(*) FROM Votes WHERE name = 'candidate3'").fetch_one(&mut *db).await.unwrap().get(0);
    let c4: u32 = sqlx::query("SELECT count(*) FROM Votes WHERE name = 'candidate4'").fetch_one(&mut *db).await.unwrap().get(0);
    Template::render("tally",context!{c1,c2,c3,c4})
}


#[catch(422)]
fn invalid() -> Template {
    Template::render("invalid",context! {})
}


#[launch]
fn rocket() -> _ {
    let (rsend, trcv) = unbounded();
    let (tsend, rrecv) = unbounded();
    launch_token_store(tsend, trcv);
    let a=rocket::build().mount("/", routes![index, userlogon, vote, recordvote, show_results])
    .register("/", catchers![invalid])
    .manage(Persist {rktrcv: rrecv, rktsnd: rsend, votekey: AtomicUsize::new(0)})
    .attach(Template::fairing()).attach(Vote::init());

    a
}
/* token store communication Method:
Channel "packets" consist of 2 element arrays of unsigned ints
The first int is the command / status indicator, The second is the cookie content
---------------------------------------------------------------------------------
Rocket to thread commands: 0: cookie lookup command (should be ack'd), 1: cookie add command (no ack) 2: cookie drop command
Thread to rocket status codes: 0: cookie is valid, 1: cookie invalid 2: critical error, tell server to panic
 */
fn launch_token_store(threadsnd: channel::Sender<(u8, String)>, threadrcv: channel::Receiver<(u8, String)>){
    thread::spawn(move || {
        let mut validlist: Vec<String> = vec!();
        loop{
            match threadrcv.try_recv(){
                Ok(out) => {
                    match &out.0{
                        0 => threadsnd.send(((!validlist.clone().contains(&out.1)).into(), out.1)).unwrap(),
                        1 => validlist.push(out.1),
                        2 => { let mut tmp = 0;
                            // This is very inefficient but for our purposes I don't care
                            for i in validlist.clone().into_iter(){
                                if &i == &out.1{
                                    validlist.remove(tmp);
                                    break;
                                }
                                tmp +=1;
                            }
                        }
                        _ => println!("Warning: bad communication from main thread"),
                    }
                }
                Err(_) => (),
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
}

fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = "mDUIuDJzLud1affbdtGjWw"; //predetermined salt
    let mut argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

async fn get_password(mut db: Connection<Vote>, ssn: u32) -> Option<String> {
    match sqlx::query("SELECT password FROM Voters WHERE ssn = ?").bind(ssn).fetch_one(&mut *db).await{
        Ok(entry) => {
            let tmp = Some(entry.get(0));
            //It's fine to just set the DB password value to 0 since the hashing algorithm that we're comparing with will never output just 0
            sqlx::query("UPDATE Voters SET password = '0' WHERE ssn = ?").bind(ssn).execute(&mut *db).await.unwrap();
            tmp},
        Err(_) => return None

    }
}
