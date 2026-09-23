use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::time::Instant;

/// How close the server is to its connection limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pressure {
    Normal,
    Elevated,
    High,
}

impl Pressure {
    /// The level that follows `self` at the given occupancy.
    ///
    /// Pressure becomes elevated at 70% and high at 90%.
    /// It only goes back down below 80% (high to elevated) and 60% (any level
    /// to normal), so that connections coming and going around a threshold
    /// don't make every idle connection reevaluate its deadline.
    fn next(self, occupied: usize, capacity: usize) -> Pressure {
        let at_least = |percent: u128| occupied as u128 * 100 >= capacity as u128 * percent;
        if !at_least(60) {
            return Pressure::Normal;
        }
        if at_least(90) {
            return Pressure::High;
        }
        match self {
            Pressure::Normal if at_least(70) => Pressure::Elevated,
            Pressure::Normal => Pressure::Normal,
            Pressure::Elevated => Pressure::Elevated,
            Pressure::High if at_least(80) => Pressure::High,
            Pressure::High => Pressure::Elevated,
        }
    }
}

/// Downstream connection slots.
///
/// A slot is reserved right after the TCP accept, before any TLS work, and is
/// released when the `Slot` guard is dropped, however the connection ends.
/// Every change of occupancy updates the published pressure level.
#[derive(Debug)]
pub(crate) struct Admission {
    capacity: usize,
    occupied: AtomicUsize,
    pressure: watch::Sender<Pressure>,
}

impl Admission {
    pub(crate) fn new(capacity: usize) -> Arc<Admission> {
        Arc::new(Admission {
            capacity,
            occupied: AtomicUsize::new(0),
            pressure: watch::Sender::new(Pressure::Normal),
        })
    }

    /// Reserves a slot, or returns `None` if all of them are taken.
    pub(crate) fn try_admit(self: &Arc<Self>) -> Option<Slot> {
        self.occupied
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |occupied| {
                (occupied < self.capacity).then(|| occupied + 1)
            })
            .ok()?;
        let slot = Slot {
            admission: Arc::clone(self),
            accepted_at: Instant::now(),
        };
        self.update_pressure();
        Some(slot)
    }

    fn update_pressure(&self) {
        // Reading the occupancy while holding the channel lock guarantees that
        // the last update always uses the latest count, whatever the order in
        // which concurrent admissions and releases get here.
        self.pressure.send_if_modified(|level| {
            let next = level.next(self.occupied.load(Ordering::Acquire), self.capacity);
            let changed = next != *level;
            *level = next;
            changed
        });
    }

    #[cfg(test)]
    pub(crate) fn occupied(&self) -> usize {
        self.occupied.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) struct Slot {
    admission: Arc<Admission>,
    /// When the slot was reserved, right after the TCP accept.
    pub(crate) accepted_at: Instant,
}

impl Slot {
    /// The receiver starts with the current level marked as seen.
    pub(crate) fn pressure(&self) -> watch::Receiver<Pressure> {
        self.admission.pressure.subscribe()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.admission.occupied.fetch_sub(1, Ordering::AcqRel);
        self.admission.update_pressure();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use super::*;

    #[test]
    fn admits_exactly_the_capacity() {
        for capacity in [1, 3] {
            let admission = Admission::new(capacity);
            let slots: Vec<_> = (0..capacity)
                .map(|_| admission.try_admit().unwrap())
                .collect();
            assert!(admission.try_admit().is_none());
            assert_eq!(admission.occupied(), capacity);
            drop(slots);
            assert_eq!(admission.occupied(), 0);
            let _slot = admission.try_admit().unwrap();
            assert_eq!(admission.try_admit().is_none(), capacity == 1);
        }
    }

    #[test]
    fn concurrent_admissions_never_exceed_the_capacity() {
        for capacity in [1, 2, 7] {
            let threads = 16;
            let admission = Admission::new(capacity);
            let barrier = Arc::new(Barrier::new(threads));
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let admission = Arc::clone(&admission);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        admission.try_admit()
                    })
                })
                .collect();
            let slots: Vec<_> = handles
                .into_iter()
                .filter_map(|handle| handle.join().unwrap())
                .collect();
            assert_eq!(slots.len(), capacity);
            assert_eq!(admission.occupied(), capacity);
            drop(slots);
            assert_eq!(admission.occupied(), 0);
        }
    }

    fn levels_while_filling_and_draining(capacity: usize) -> (Vec<Pressure>, Vec<Pressure>) {
        let admission = Admission::new(capacity);
        let receiver = admission.pressure.subscribe();
        let mut slots = vec![];
        let mut filling = vec![*receiver.borrow()];
        for _ in 0..capacity {
            slots.push(admission.try_admit().unwrap());
            filling.push(*receiver.borrow());
        }
        let mut draining = vec![];
        while slots.pop().is_some() {
            draining.push(*receiver.borrow());
        }
        (filling, draining)
    }

    #[test]
    fn pressure_follows_occupancy_with_hysteresis() {
        use Pressure::*;
        let (filling, draining) = levels_while_filling_and_draining(10);
        // Occupancy 0 to 10.
        assert_eq!(
            filling,
            [
                Normal, Normal, Normal, Normal, Normal, Normal, Normal, Elevated, Elevated, High,
                High
            ]
        );
        // Occupancy 9 down to 0.
        assert_eq!(
            draining,
            [High, High, Elevated, Elevated, Normal, Normal, Normal, Normal, Normal, Normal]
        );
    }

    #[test]
    fn pressure_transitions() {
        use Pressure::*;
        let cases = [
            (Normal, 69, Normal),
            (Normal, 70, Elevated),
            (Normal, 89, Elevated),
            (Normal, 90, High),
            (Elevated, 60, Elevated),
            (Elevated, 59, Normal),
            (Elevated, 89, Elevated),
            (Elevated, 90, High),
            (High, 80, High),
            (High, 79, Elevated),
            (High, 60, Elevated),
            (High, 59, Normal),
            (High, 0, Normal),
            (Normal, 100, High),
        ];
        for (from, occupied, to) in cases {
            assert_eq!(from.next(occupied, 100), to, "{:?} at {}%", from, occupied);
        }
    }

    #[test]
    fn pressure_with_small_limits() {
        use Pressure::*;
        assert_eq!(
            levels_while_filling_and_draining(1),
            (vec![Normal, High], vec![Normal])
        );
        assert_eq!(
            levels_while_filling_and_draining(2),
            (vec![Normal, Normal, High], vec![Normal, Normal])
        );
        assert_eq!(
            levels_while_filling_and_draining(3),
            (
                vec![Normal, Normal, Normal, High],
                vec![Elevated, Normal, Normal]
            )
        );
    }

    #[test]
    fn pressure_with_huge_limits() {
        use Pressure::*;
        assert_eq!(Normal.next(usize::MAX, usize::MAX), High);
        assert_eq!(High.next(usize::MAX / 2, usize::MAX), Normal);
        let seventy_percent = (usize::MAX as u128 * 7).div_ceil(10) as usize;
        assert_eq!(Normal.next(seventy_percent, usize::MAX), Elevated);
        assert_eq!(Normal.next(seventy_percent - 1, usize::MAX), Normal);
    }

    #[test]
    fn receivers_are_only_notified_when_the_level_changes() {
        let admission = Admission::new(10);
        let mut slots = vec![admission.try_admit().unwrap()];
        let mut receiver = slots[0].pressure();
        for _ in 1..6 {
            slots.push(admission.try_admit().unwrap());
            assert!(!receiver.has_changed().unwrap());
        }
        slots.push(admission.try_admit().unwrap());
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow_and_update(), Pressure::Elevated);
        slots.push(admission.try_admit().unwrap());
        assert!(!receiver.has_changed().unwrap());
        slots.truncate(6);
        assert!(!receiver.has_changed().unwrap());
        slots.truncate(5);
        assert!(receiver.has_changed().unwrap());
        assert_eq!(*receiver.borrow_and_update(), Pressure::Normal);
    }

    #[test]
    fn concurrent_admissions_and_releases_leave_a_consistent_level() {
        let capacity = 20;
        let admission = Admission::new(capacity);
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let admission = Arc::clone(&admission);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..2000 {
                        let slots: Vec<_> = (0..3).filter_map(|_| admission.try_admit()).collect();
                        drop(slots);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(admission.occupied(), 0);
        assert_eq!(*admission.pressure.borrow(), Pressure::Normal);

        let slots: Vec<_> = (0..capacity)
            .map(|_| admission.try_admit().unwrap())
            .collect();
        assert_eq!(*admission.pressure.borrow(), Pressure::High);
        drop(slots);
    }

    #[test]
    fn slot_is_released_when_its_task_is_dropped() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let admission = Admission::new(1);
        let slot = admission.try_admit().unwrap();
        let task = runtime.spawn(async move {
            let _slot = slot;
            std::future::pending::<()>().await
        });
        assert_eq!(admission.occupied(), 1);
        task.abort();
        let _ = runtime.block_on(task);
        assert_eq!(admission.occupied(), 0);

        let slot = admission.try_admit().unwrap();
        runtime.spawn(async move {
            let _slot = slot;
            std::future::pending::<()>().await
        });
        drop(runtime);
        assert_eq!(admission.occupied(), 0);
    }
}
