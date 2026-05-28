//! Fractional ordering for reorderable lists (statuses, board columns, …).
//!
//! Items carry an `f64` rank. Inserting between two neighbours uses the
//! midpoint, so a single-row update places an item anywhere — no rewrite of
//! the whole list. When two neighbours get too close for an `f64` midpoint,
//! [`rank_between`] returns `None`, signalling the caller to renormalize
//! (reassign `1.0, 2.0, 3.0, …`).

/// Gap used when appending to the end of a list.
pub const APPEND_GAP: f64 = 1.0;

/// Compute a rank strictly between `before` and `after`.
///
/// - both `None` → first item (`APPEND_GAP`)
/// - `before` only → append after it
/// - `after` only → prepend before it
/// - both → midpoint, or `None` if no representable value fits (renormalize)
#[must_use]
pub fn rank_between(before: Option<f64>, after: Option<f64>) -> Option<f64> {
    match (before, after) {
        (None, None) => Some(APPEND_GAP),
        (Some(b), None) => Some(b + APPEND_GAP),
        (None, Some(a)) => Some(a - APPEND_GAP),
        (Some(b), Some(a)) => {
            // Guard against caller passing them in the wrong order.
            let (lo, hi) = if b <= a { (b, a) } else { (a, b) };
            let mid = lo + (hi - lo) / 2.0;
            if mid > lo && mid < hi {
                Some(mid)
            } else {
                None
            }
        }
    }
}

/// Reassign evenly-spaced ranks (`1.0, 2.0, …`) to a list already in the
/// desired order. Used as the renormalization fallback.
#[must_use]
#[allow(clippy::cast_precision_loss)] // list sizes are tiny; no precision risk
pub fn normalized_ranks(count: usize) -> Vec<f64> {
    (0..count).map(|i| (i as f64) + APPEND_GAP).collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::cast_lossless,
        clippy::expect_used,
        clippy::type_complexity,
        clippy::single_match_else
    )]
    use rand::Rng;

    use super::*;

    #[test]
    fn basic_cases() {
        assert_eq!(rank_between(None, None), Some(1.0));
        assert_eq!(rank_between(Some(3.0), None), Some(4.0));
        assert_eq!(rank_between(None, Some(2.0)), Some(1.0));
        assert_eq!(rank_between(Some(1.0), Some(2.0)), Some(1.5));
    }

    #[test]
    fn returns_none_when_no_midpoint_fits() {
        // Two adjacent f64 values have no representable midpoint between them.
        let a = 1.0_f64;
        let b = f64::from_bits(a.to_bits() + 1);
        assert_eq!(rank_between(Some(a), Some(b)), None);
    }

    /// A list model with id+rank; supports moving an item between neighbours,
    /// renormalizing when the midpoint can't fit.
    struct OrderedList {
        items: Vec<(u32, f64)>, // (id, rank), kept sorted by rank
    }

    impl OrderedList {
        fn sorted_ids(&self) -> Vec<u32> {
            let mut v = self.items.clone();
            v.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap());
            v.into_iter().map(|(id, _)| id).collect()
        }

        fn renormalize(&mut self) {
            self.items.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap());
            for (i, item) in self.items.iter_mut().enumerate() {
                item.1 = (i as f64) + 1.0;
            }
        }

        /// Move `id` to sit at position `pos` in the current sorted order.
        fn move_to(&mut self, id: u32, pos: usize) {
            let order = self.sorted_ids();
            let filtered: Vec<u32> = order.into_iter().filter(|x| *x != id).collect();
            let pos = pos.min(filtered.len());
            let before = pos
                .checked_sub(1)
                .and_then(|i| filtered.get(i))
                .and_then(|bid| self.rank_of(*bid));
            let after = filtered.get(pos).and_then(|aid| self.rank_of(*aid));
            match rank_between(before, after) {
                Some(rank) => self.set_rank(id, rank),
                None => {
                    // Renormalize, then retry once.
                    self.renormalize();
                    let before = pos
                        .checked_sub(1)
                        .and_then(|i| filtered.get(i))
                        .and_then(|bid| self.rank_of(*bid));
                    let after = filtered.get(pos).and_then(|aid| self.rank_of(*aid));
                    let rank = rank_between(before, after).expect("fits after renormalize");
                    self.set_rank(id, rank);
                }
            }
        }

        fn rank_of(&self, id: u32) -> Option<f64> {
            self.items.iter().find(|(i, _)| *i == id).map(|(_, r)| *r)
        }
        fn set_rank(&mut self, id: u32, rank: f64) {
            if let Some(item) = self.items.iter_mut().find(|(i, _)| *i == id) {
                item.1 = rank;
            }
        }
    }

    #[test]
    fn property_10k_random_reorders_preserve_total_order_and_uniqueness() {
        let n = 20u32;
        let mut list = OrderedList {
            items: (0..n).map(|i| (i, (i as f64) + 1.0)).collect(),
        };
        let mut rng = rand::thread_rng();

        for _ in 0..10_000 {
            let id = rng.gen_range(0..n);
            let pos = rng.gen_range(0..n as usize);
            list.move_to(id, pos);

            // Invariant 1: every id still present exactly once.
            let ids = list.sorted_ids();
            assert_eq!(ids.len(), n as usize);
            let mut uniq = ids.clone();
            uniq.sort_unstable();
            uniq.dedup();
            assert_eq!(uniq.len(), n as usize, "ids must stay unique");

            // Invariant 2: ranks strictly increasing (a total order with no ties).
            let mut ranks: Vec<f64> = list.items.iter().map(|(_, r)| *r).collect();
            ranks.sort_by(|a, b| a.partial_cmp(b).unwrap());
            for w in ranks.windows(2) {
                assert!(w[1] > w[0], "ranks must be strictly increasing: {w:?}");
            }
        }
    }
}
