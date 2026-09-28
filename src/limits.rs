use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub const BUSY: &str = "LARP busy; retry later";

pub struct Counter {
    active: AtomicUsize,
    max: usize,
}

pub struct Permit(Arc<Counter>);

impl Counter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            max,
        })
    }

    pub fn acquire(self: &Arc<Self>) -> Option<Permit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max).then_some(count + 1)
            })
            .ok()
            .map(|_| Permit(Arc::clone(self)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn configured(name: &str, default: usize, ceiling: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| format!("{name} must be a number"))?;
            if parsed == 0 || parsed > ceiling {
                return Err(format!("{name} must be between 1 and {ceiling}"));
            }
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!("{name} is not valid UTF-8")),
    }
}

#[cfg(test)]
mod tests {
    use super::Counter;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn full_counter_is_retryable_after_release() {
        let counter = Counter::new(2);
        let first = counter.acquire().unwrap();
        let second = counter.acquire().unwrap();
        assert!(counter.acquire().is_none());
        drop(first);
        assert!(counter.acquire().is_some());
        drop(second);
    }

    #[test]
    fn admits_parallel_work_up_to_limit() {
        let count = 32;
        let counter = Counter::new(count);
        let ready = Arc::new(Barrier::new(count + 1));
        let release = Arc::new(Barrier::new(count + 1));
        let workers: Vec<_> = (0..count)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let ready = Arc::clone(&ready);
                let release = Arc::clone(&release);
                thread::spawn(move || {
                    let _permit = counter.acquire().unwrap();
                    ready.wait();
                    release.wait();
                })
            })
            .collect();
        ready.wait();
        assert!(counter.acquire().is_none());
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(counter.acquire().is_some());
    }
}
