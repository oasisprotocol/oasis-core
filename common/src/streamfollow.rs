use futures::BoxStream;
use futures::Stream;
use error::Error;
use std::thread::sleep;

fn pseudo() {
    let init = unimplemented!();
    let resume = unimplemented!();
    let to_bookmark = unimplemented!();
    let backoff_init = unimplemented!();
    let backoff_advance = unimplemented!();
    let is_permanent = unimplemented!();
    let mut last = None;
    'resumes: loop {
        let items;
        let mut backoff = backoff_init();
        loop {
            let stream = if let Some(bookmark) = last {
                resume(bookmark)
            } else {
                init()
            };
            match stream.into_future().wait() /* last, backoff, stream */ {
                Ok(Some(first, rest)) => {
                    if let Some(bookmark) = last {
                        assert_eq!(bookmark, to_bookmark(first));
                    } else {
                        last = to_bookmark(first);
                    }
                    items = rest;
                    break;
                }
                Ok(None) => {
                    error!("no blocks in the chain");
                }
                Err(e) => {
                    if is_permanent(e) {
                        send_error(e);
                        break 'resumes;
                    } else {
                        error!("stream error (early) {:?}", e);
                    }
                }
            };
            trace!("retrying in {}", backoff);
            sleep(backoff) /* last, backoff */;
            backoff = backoff_advance(backoff);
        }
        let iter = items.wait();
        loop {
            match iter.next() /* last, iter */ {
                Some(Ok(item)) => {
                    last = to_bookmark(item);
                    send(item);
                }
                Some(Err(e)) => {
                    if is_permanent(e) {
                        send_error(e);
                        break 'resumes;
                    } else {
                        error!("stream error (late) {:?}", e);
                        break;
                    }
                }
                None => {
                    break 'resumes;
                }
            }
        }
    }
}
