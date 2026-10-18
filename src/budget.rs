//! Caps the memory held by operations running at the same time.

use std::sync::{Condvar, Mutex};

pub(crate) struct Budget {
    capacity: u64,
    used: Mutex<u64>,
    released: Condvar,
}

pub(crate) struct Permit<'a> {
    budget: &'a Budget,
    amount: u64,
}

impl Budget {
    pub fn new(capacity: u64) -> Self {
        Self {
            capacity,
            used: Mutex::new(0),
            released: Condvar::new(),
        }
    }

    /// Waits until `amount` bytes fit. A request larger than the whole budget
    /// waits until nothing else is held and then runs alone.
    pub fn acquire(&self, amount: u64) -> Permit<'_> {
        let amount = amount.min(self.capacity);
        let mut used = self.used.lock().unwrap();
        while *used + amount > self.capacity {
            used = self.released.wait(used).unwrap();
        }
        *used += amount;
        Permit { budget: self, amount }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.budget.used.lock().unwrap() -= self.amount;
        self.budget.released.notify_all();
    }
}
