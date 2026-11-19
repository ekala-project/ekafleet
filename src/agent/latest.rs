//! One job at a time, latest submission wins.
//!
//! The agent fetches service closures in the background of its message
//! loop: a fetch can take minutes, and secrets, commands and peer updates
//! must not wait for it. A desired state that arrives while a fetch runs
//! replaces any one already queued, so a burst of updates costs at most one
//! extra fetch, of the newest state.

use std::future::Future;
use std::pin::Pin;

type Job<'a, O> = Pin<Box<dyn Future<Output = O> + Send + 'a>>;

pub struct Latest<'a, I, O> {
    start: Box<dyn Fn(I) -> Job<'a, O> + Send + 'a>,
    running: Option<Job<'a, O>>,
    queued: Option<I>,
}

impl<'a, I, O> Latest<'a, I, O> {
    pub fn new<F, Fut>(start: F) -> Self
    where
        F: Fn(I) -> Fut + Send + 'a,
        Fut: Future<Output = O> + Send + 'a,
    {
        Self {
            start: Box::new(move |input| Box::pin(start(input))),
            running: None,
            queued: None,
        }
    }

    /// Start `input` now if nothing runs, else queue it in place of any
    /// input already waiting.
    pub fn submit(&mut self, input: I) {
        if self.running.is_none() {
            self.running = Some((self.start)(input));
        } else {
            self.queued = Some(input);
        }
    }

    /// The output of the running job, once it finishes (never, while idle).
    /// The queued input, if any, starts as it returns. Cancel-safe: the
    /// running job stays in place when this future is dropped.
    pub async fn next(&mut self) -> O {
        let Some(running) = self.running.as_mut() else {
            return std::future::pending().await;
        };
        let output = running.await;
        self.running = self.queued.take().map(|input| (self.start)(input));
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn a_burst_runs_the_first_and_the_newest_job() {
        let started = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = started.clone();
        let (release, gate) = oneshot::channel::<()>();
        let gate = std::sync::Mutex::new(Some(gate));
        let mut latest = Latest::new(move |n: u32| {
            log.lock().unwrap().push(n);
            let gate = if n == 1 {
                gate.lock().unwrap().take()
            } else {
                None
            };
            async move {
                if let Some(gate) = gate {
                    gate.await.unwrap();
                }
                n
            }
        });

        latest.submit(1);
        latest.submit(2);
        latest.submit(3);

        // The first job blocks; waiting on it does not hold anything up.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), latest.next())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert_eq!(latest.next().await, 1);
        assert_eq!(latest.next().await, 3);
        assert_eq!(*started.lock().unwrap(), vec![1, 3]);

        // Idle: nothing comes out until something is submitted.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), latest.next())
                .await
                .is_err()
        );
        latest.submit(4);
        assert_eq!(latest.next().await, 4);
    }
}
