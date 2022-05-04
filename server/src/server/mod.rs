mod utils;

use std::convert::Infallible;
use borsh::{BorshSerialize, BorshDeserialize};
use rand::RngCore;
use warp::{Filter, hyper::body::Bytes};
use lazy_static::lazy_static;
use async_stream::stream;
use base64::encode;
use futures::TryStreamExt;
use tracing::{error, debug};

use common::api::{VERSION, request, response};
use crate::{database::{Database, user, challenge, message}, Config};

lazy_static! {
    static ref VERSION_PACKED: Vec<u8> = response::Version(VERSION).try_to_vec().expect("Cannot pack version response");
}

async fn pong() -> Result<impl warp::Reply, Infallible> {
    debug!("New ping request");
    Ok("")
}

async fn version() -> Result<impl warp::Reply, Infallible> {
    debug!("New version request");
    Ok(VERSION_PACKED.clone())
}

async fn challenge(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    debug!("New challenge request");
    let mut resp = response::Challenge { challenge: vec![], status: response::Status::ReqErr };
    match request::VerifiedRequest::try_from_slice(&req) {
        Ok(re) => {
            match re.public_key.try_to_vec() {
                Ok(pk_ser) => {
                    match challenge::get(&db, &pk_ser).await {
                        Ok(Some(session)) => {
                            match re.public_key.verify_sig(&re.req, &re.sig) {
                                Ok(true) => {
                                    match request::GenericRequest::try_from_slice(&re.req) {
                                        Ok(v) => {
                                            if v.challenge.eq(&session.key) {
                                                let mut rand_bytes = [0_u8; 128]; 
                                                let mut seed: rand::rngs::StdRng = rand::SeedableRng::from_entropy();
                                                match seed.try_fill_bytes(&mut rand_bytes) {
                                                    Ok(_) => {
                                                        match challenge::set(&db, &pk_ser, &rand_bytes, chrono::Utc::now().timestamp()).await {
                                                            Ok(_) => {
                                                                resp.status    = response::Status::Ok;
                                                                resp.challenge = rand_bytes.to_vec();
                                                            },
                                                            Err(_) => ()
                                                        }
                                                    },
                                                    Err(_) => {}
                                                }
                                            } else {
                                            }
                                        },
                                        Err(_) => ()
                                    }
                                },
                                Ok(false) => {
                                    resp.status = response::Status::SigError;
                                },
                                Err(_) => ()
                            }
                        },
                        Ok(None) => resp.status = response::Status::UnknewnPublicKey,
                        Err(_) => ()
                    }
                }
                _ => ()
            }
        },
        Err(_) => ()
    }
    Ok(resp.try_to_vec().expect("Can't serialize subscribe response"))
}

async fn subscribe(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    debug!("New subscribe request");
    let mut resp = response::Subscribe { status: response::Status::ReqErr, challenge: vec![] };
    match request::Subscribe::try_from_slice(&req) {
        Ok(sub) => {
            match sub.public_key.try_to_vec() {
                Ok(v) => {
                    match sub.public_key.verify_sig(&v, &sub.sig) {
                        Ok(true) => {
                            match user::create(&db, &v).await {
                                Ok(_) => {
                                    let mut rand_bytes = [0_u8; 128]; 
                                    let mut seed: rand::rngs::StdRng = rand::SeedableRng::from_entropy();
                                    match seed.try_fill_bytes(&mut rand_bytes) {
                                        Ok(_) => {
                                            match challenge::set(&db, &v, &rand_bytes, chrono::Utc::now().timestamp()).await {
                                                Ok(_) => {
                                                    resp.challenge = rand_bytes.to_vec();
                                                    resp.status    = response::Status::Ok;
                                                },
                                                Err(e) => error!("Error updating challlenge in database: {}", e)
                                            }
                                        },
                                        Err(_) => {}
                                    }
                                },
                                Err(_) => ()
                            }
                        },
                        Ok(false) => (),
                        Err(e) => error!("Error verifying signature for key {}: {}", sub.public_key, e)
                    }
                }
                _ => ()
            }
        },
        Err(_) => ()
    }
    Ok(resp.try_to_vec().expect("Can't serialize subscribe response"))
}

async fn unsubscribe(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    let mut resp = response::Unsubscribe { status: response::Status::ReqErr };
    match request::VerifiedRequest::try_from_slice(&req) {
        Ok(re) => {
            match (re.public_key.try_to_vec(), request::GenericRequest::try_from_slice(&re.req)) {
                (Ok(pk_ser), Ok(unsub)) => {
                    match utils::session_valid(&db, &pk_ser, &unsub.challenge).await {
                        Ok(v) => {
                            match v {
                                e @ response::Status::Ok => {
                                    match user::remove(&db, &pk_ser).await {
                                        Ok(_) => {
                                            resp.status = e;
                                        },
                                        Err(_) => ()
                                    }
                                },
                                e @ _ => {
                                    resp.status = e;
                                }
                            }
                        },
                        Err(_) => ()
                    }
                }
                _ => ()
            }
        }
        Err(_) => ()
    }
    Ok(resp.try_to_vec().expect("Can't serialize subscribe response"))
}

async fn send_message(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    let mut resp = response::SendMessage { status: response::Status::ReqErr };
    match request::VerifiedRequest::try_from_slice(&req) {
        Ok(re) => {
            match (re.public_key.try_to_vec(), request::SendMessage::try_from_slice(&re.req)) {
                (Ok(pk_ser), Ok(message)) => {
                    match utils::session_valid(&db, &pk_ser, &message.challenge).await {
                        Ok(v) => {
                            match v {
                                e @ response::Status::Ok => {
                                    match message::add(&db, &message.destination, &message.message).await {
                                        Ok(_) => {
                                            resp.status = e;
                                        },
                                        Err(e) => {
                                            error!("Error sending message: {}", e);
                                        }
                                    }
                                },
                                e @ _ => {
                                    resp.status = e;
                                }
                            }
                        },
                        Err(_) => ()
                    }
                }
                _ => ()
            }
        }
        Err(_) => ()
    }
    Ok(resp.try_to_vec().expect("Can't serialize subscribe response"))
}

async fn message_received(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    let mut resp = response::MessageReceived { status: response::Status::ReqErr };
    match request::VerifiedRequest::try_from_slice(&req) {
        Ok(re) => {
            match (re.public_key.try_to_vec(), request::MessageReceived::try_from_slice(&re.req)) {
                (Ok(pk_ser), Ok(confirm)) => {
                    match utils::session_valid(&db, &pk_ser, &confirm.challenge).await {
                        Ok(v) => {
                            match v {
                                e @ response::Status::Ok => {
                                    match message::remove(&db, &pk_ser, confirm.id).await {
                                        Ok(_) => {
                                            resp.status = e;
                                        },
                                        Err(_) => ()
                                    }
                                },
                                e @ _ => {
                                    resp.status = e;
                                }
                            }
                        },
                        Err(_) => ()
                    }
                }
                _ => ()
            }
        }
        Err(_) => ()
    }
    Ok(resp.try_to_vec().expect("Can't serialize subscribe response"))
}

async fn message_event(db: Database, req: Bytes) -> Result<impl warp::Reply, Infallible> {
    let stream = stream! {
        match request::VerifiedRequest::try_from_slice(&req) {
            Ok(re) => {
                match (re.public_key.try_to_vec(), request::MessageNotification::try_from_slice(&re.req)) {
                    (Ok(pk_ser), Ok(message)) => {
                        match utils::session_valid(&db, &pk_ser, &message.challenge).await {
                            Ok(v) => {
                                match v {
                                    response::Status::Ok => {
                                        let mut msg_stream = message::poll(&db, pk_ser, message.id).await;
                                        loop {
                                            match msg_stream.try_next().await {
                                                Ok(v) => {
                                                    match v {
                                                        Some(v) => {
                                                            let id = format!("{},{}", v.id, v.timestamp);
                                                            yield Ok(warp::sse::Event::default().event("m").id(id).data(encode(&v.message))) as Result<warp::sse::Event, Infallible>
                                                        },
                                                        None => break
                                                    }
                                                },
                                                Err(e) => {
                                                    error!("Error occured in message notification: {}", e);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                     _ => (),
                                }
                            }
                            Err(_) => ()
                        }
                    }
                    _ => ()
                }
            }
            Err(_) => ()
        }
        yield Ok(warp::sse::Event::default().event("e").data(
                encode(&response::MessageEvent { status: response::Status::ReqErr }.try_to_vec().expect("Can't serialize response"))
                )) as Result<warp::sse::Event, Infallible>;
    };
    Ok(Box::new(warp::sse::reply(warp::sse::keep_alive().stream(stream))))
}

pub async fn serve(db: Database, conf: &Config) {
    let db = warp::any().map(move || db.clone());

    let pong_route = warp::get()
        .and(warp::path("ping"))
        .and_then(pong);

    let version_route = warp::get()
        .and(warp::path("version"))
        .and_then(version);

    let subscribe_route = warp::post()
        .and(warp::path("sub"))
        .and(warp::body::content_length_limit(512))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(subscribe);

    let challenge_route = warp::post()
        .and(warp::path("challenge"))
        .and(warp::body::content_length_limit(512))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(challenge);

    let unsubscribe_route = warp::post()
        .and(warp::path("unsub"))
        .and(warp::body::content_length_limit(1024))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(unsubscribe);

    let send_message_route = warp::post()
        .and(warp::path("sndmsg"))
        .and(warp::body::content_length_limit(8192))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(send_message);

    let message_received_route = warp::post()
        .and(warp::path("msgack"))
        .and(warp::body::content_length_limit(512))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(message_received);

    let message_event_route = warp::post()
        .and(warp::path("msgevent"))
        .and(warp::body::content_length_limit(512))
        .and(db.clone())
        .and(warp::body::bytes())
        .and_then(message_event);

    let routes = pong_route
        .or(version_route)
        .or(subscribe_route)
        .or(challenge_route)
        .or(unsubscribe_route)
        .or(send_message_route)
        .or(message_received_route)
        .or(message_event_route);

    warp::serve(routes)
        .tls()
        .cert_path(&conf.certificate_path)
        .key_path(&conf.key_path)
        .run(([127, 0, 0, 1], conf.port))
        .await;
}
