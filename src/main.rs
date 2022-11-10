#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::{form::Form, http::{Cookie, CookieJar}, State, response::Redirect};
use std::{thread, time, time::Duration, net::IpAddr};
use crossbeam::channel::{self, unbounded};
use argon2::{password_hash::PasswordHasher,Argon2};
use rocket_db_pools::{sqlx::{self,Row}, Database, Connection};
use rand_core::{RngCore, OsRng};

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
#[derive(Clone)]
struct Address {
    addr: IpAddr,
    counter: i32,
    banbool: bool,
    banstart: time::SystemTime,
}

struct Persist {
    rktsnd: channel::Sender<(u8, String)>,
    rktrcv: channel::Receiver<(u8, String)>,
    adsnd: channel::Sender<(u8, IpAddr)>,
    adrcv: channel::Receiver<bool>
}

#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
async fn userlogon(db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, user: Form<User<'_>>, addr: IpAddr) -> Redirect{
    let authok: bool;
    match hash_password(user.password.to_string()){ // argon 2 salt and hash
        Ok(hash) => {
            // retrieve the user record from sqlite
            match get_password(db, user.ssn).await{ 
                // authok is true if the known hash and entered password's hash match
                Some(tmp) => authok = hash == tmp, 
                None => authok = false,
            }
            },
        // If the user input fails automatic sanitization, send them back to login
        Err(_) => return Redirect::to(uri!(index())), 
    }
    if authok{
        println!("authentication OK");
        state.adsnd.send((0, addr)).unwrap();
        // get next auth number in sequence
        let rndm = OsRng.next_u32().to_string();
        // give client encrypted cookie with sequence number as payload
        cookies.add_private(Cookie::new("votertoken", rndm.clone())); 
        // tell authtoken thread to add new number to list of authorized keys
        state.rktsnd.send((1, rndm)).unwrap(); 
        // redirect authorized user to voting form
        return Redirect::to(uri!(vote()));
    }
    // redirect unauthorized user back to login
    Redirect::to(uri!(index()))
}

#[get("/vote")]
fn vote(state: &State<Persist>, cookies: &CookieJar<'_>, addr: IpAddr) -> Template {
    let status: u8;
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
async fn recordvote(mut db: Connection<Vote>, state: &State<Persist>, cookies: &CookieJar<'_>, vote: Form<Ballot<'_>>, addr: IpAddr) -> Redirect{
    let status: u8;
    let key: String;
    state.adsnd.send((1, addr)).unwrap();
    // retrieve cookie from user
    if state.adrcv.recv_timeout(Duration::from_millis(10)).unwrap(){
        return Redirect::to(uri!(index()));
    }
    match cookies.get_private("votertoken"){
        Some(crumb) => {
            // get auth sequence number from cookie
            key = crumb.value().to_string();
            // send verification request to authtoken thread
            state.rktsnd.send((0, key.clone())).unwrap();
            // wait for authtoken responce
            loop{
                let out = state.rktrcv.recv_timeout(Duration::from_millis(10)).unwrap();
                if out.1 == key{
                    status = out.0;
                    break;
                }
            }
            //remove cookie from user
            cookies.remove_private(crumb);
        }
        //if the user doesn't have a cookie, send them to login
        None => return Redirect::to(uri!(index())),
    }
    if status == 0{
        // run sql command to incriment vote tally for selected candidate (form input is santitized automatically)
        sqlx::query("UPDATE Votes SET count = (SELECT count FROM Votes WHERE name = ?)+1 WHERE name = ?;")
        .bind(vote.candidate).bind(vote.candidate).execute(&mut *db).await.unwrap();
        // tell authtoken thread to invalidate user's sequence number so a replay cannot be done
        state.rktsnd.send((2, key)).unwrap();
        // tell user everything worked
        Redirect::to(uri!(done()))
    }
    else{ 
    // assume something's gone wrong and direct user back to logon page
    Redirect::to(uri!(index()))
    }
    
}

#[get("/results")]
async fn show_results(mut db: Connection<Vote>) -> Template{
    let c1: u32 = sqlx::query("SELECT count FROM Votes WHERE name = 'candidate1'").fetch_one(&mut *db).await.unwrap().get(0);
    let c2: u32 = sqlx::query("SELECT count FROM Votes WHERE name = 'candidate2'").fetch_one(&mut *db).await.unwrap().get(0);
    let c3: u32 = sqlx::query("SELECT count FROM Votes WHERE name = 'candidate3'").fetch_one(&mut *db).await.unwrap().get(0);
    let c4: u32 = sqlx::query("SELECT count FROM Votes WHERE name = 'candidate4'").fetch_one(&mut *db).await.unwrap().get(0);
    Template::render("tally",context!{c1,c2,c3,c4})
}

#[get("/done")]
fn done() -> Template{
    Template::render("done",context!{})
}


#[catch(422)]
fn invalid() -> Template {
    Template::render("invalid",context! {})
}


#[launch]
fn rocket() -> _ {
    let (rsend, trcv) = unbounded();
    let (tsend, rrecv) = unbounded();
    let (adsnd, tadrcv) = unbounded();
    let (tadsnd, adrcv) = unbounded();
    launch_token_store(tsend, trcv);
    launch_address_store(tadsnd, tadrcv);
    let a=rocket::build().mount("/", routes![index, userlogon, vote, recordvote, show_results, done])
    .register("/", catchers![invalid])
    .manage(Persist {rktrcv: rrecv, rktsnd: rsend, adrcv: adrcv, adsnd: adsnd})
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
                    println!("Valid keys: {:?}",&validlist);
                }
                Err(_) => (),
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
}
// 0 - IP address login success
// 1 - IP address vote POST
// 2 - query
fn launch_address_store(tadsnd: channel::Sender<bool>, tadrcv: channel::Receiver<(u8, IpAddr)>){
    thread::spawn(move || {
        let mut addresslist: Vec<Address> = vec!();
        loop{
            match tadrcv.try_recv(){
                Ok(msg) => {
                    let mut found_entry = false;
                    for a in addresslist.iter_mut(){
                        if &a.addr == &msg.1 {
                            found_entry = true;
                            match msg.0{
                                0 => a.counter += 1,
                                1 => {
                                    a.counter -= 1;
                                    if a.counter < -10{
                                    a.banbool=true;
                                    a.banstart = time::SystemTime::now();
                                    a.counter = 0;
                                    }
                                    tadsnd.send(a.banbool.clone()).unwrap();
                                }
                                _ => ()
                            }
                        }
                        if a.banbool{
                        match time::SystemTime::now().duration_since(a.banstart){
                            Ok(tm) => if tm.as_secs() > 3600 {a.banbool = false},
                            Err(_) => ()
                        }
                    }
                    }
                    if !found_entry {
                        let tmp = Address{addr:msg.1, counter: 0, banbool: false, banstart: time::SystemTime::now()};
                        addresslist.push(tmp);
                    }
                },
                Err(_) =>()
            }
        }
    });
}

fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = "mDUIuDJzLud1affbdtGjWw"; //predetermined salt
    let argon2 = Argon2::default();
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
