#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::{form::{self, Form}, http::{Cookie, CookieJar}, State};
use rand_core::{RngCore, OsRng};
use std::{thread, time::Duration, result};
use crossbeam::channel::{self, unbounded};
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(FromForm, Debug)]
struct User<'r> {
    ssn: u64,
    password: &'r str,
}

#[derive(FromForm, Debug)]
struct Ballot<'r> {
    candidate: &'r str,
}

#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
fn userlogon(state: &State<Persist>, cookies: &CookieJar<'_>, user: Form<User<'_>>) -> Template{
    println!("{:?}",&user);
    let authok = user.password == "1234";
    if authok{
        let rndm: String = (state.votekey.fetch_add(1, Ordering::Relaxed) + 1).to_string();
        cookies.add_private(Cookie::new("votertoken", rndm.clone()));
        state.rktsnd.send((1, rndm)).unwrap();
    }
    Template::render("auth",context!{authok})
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
fn recordvote(state: &State<Persist>, cookies: &CookieJar<'_>, vote: Form<Ballot<'_>>) -> Template{
    println!("{:?}",&vote);
    let mut status = 1;
    let key: String;
    match cookies.get_private("votertoken"){
        Some(crumb) => {
            key = crumb.value().to_string();
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
        None => return Template::render("auth",context!{authok: false}),
    }
    if status == 0{
        // do databasey stuff
        println!("Key {} voted for {}",&key,vote.candidate);
        state.rktsnd.send((2, key)).unwrap();
    }
    Template::render("done",context!{})
    
}


#[catch(422)]
fn invalid() -> Template {
    Template::render("invalid",context! {})
}

struct Persist {
    rktsnd: channel::Sender<(u8, String)>,
    rktrcv: channel::Receiver<(u8, String)>,
    votekey: AtomicUsize,
}


#[launch]
fn rocket() -> _ {
    let (rsend, trcv) = unbounded();
    let (tsend, rrecv) = unbounded();
    launch_token_store(tsend, trcv);
    println!("this is a test");
    rocket::build().mount("/", routes![index, userlogon, vote, recordvote])
    .register("/", catchers![invalid])
    .manage(Persist {rktrcv: rrecv, rktsnd: rsend, votekey: AtomicUsize::new(0)})
    .attach(Template::fairing())
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
                    println!("Got command {:?}",out.clone()); 
                    match &out.0{
                        0 => threadsnd.send((validlist.clone().contains(&out.1).into(), out.1)).unwrap(),
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