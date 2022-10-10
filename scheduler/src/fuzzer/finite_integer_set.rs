use std::{
    borrow::Borrow,
    collections::{hash_set, HashSet},
    fmt, hash,
    marker::PhantomData,
};

use fuzztruction_shared::types::PatchPointID;
use rand::{
    prelude::{IteratorRandom, SliceRandom},
    thread_rng,
};
use serde::{Deserialize, Serialize};

use crate::constants::{MAX_PATCHPOINT_CNT, MAX_QUEUE_ENTRY_CNT};

use super::queue::QueueEntryId;

pub type PatchPointIDSet = FiniteIntegerSet<PatchPointID, MAX_PATCHPOINT_CNT>;
pub type QueueIDDSet = FiniteIntegerSet<QueueEntryId, MAX_QUEUE_ENTRY_CNT>;

#[derive(Clone, Serialize, Deserialize)]
pub struct FiniteIntegerSet<U, const N: usize> {
    data: Vec<u8>,
    max_val: usize,
    phantom: PhantomData<U>,
}

impl<U, const N: usize> fmt::Debug for FiniteIntegerSet<U, N>
where
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
    usize: From<U>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ret = f.debug_struct("FiniteIntegerSet");
        ret.field("max_val", &self.max_val);

        if self.max_val > 32 {
            ret.finish_non_exhaustive()
        } else {
            ret.field("entries", &self.entries()).finish()
        }
    }
}

/// A set that can contain all integers from 0 to `N`.
impl<U, const N: usize> FiniteIntegerSet<U, N>
where
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
    usize: From<U>,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let vec_size = N / 8 + 1;

        FiniteIntegerSet {
            data: vec![0; vec_size],
            max_val: N,
            phantom: PhantomData,
        }
    }

    fn idx(&self, elem: usize) -> (usize, usize) {
        if elem <= self.max_val {
            return (elem / 8, elem % 8);
        }
        panic!("Element {} is OOB for {:#?}", elem, self);
    }

    /// Insert `element` and returns true if it was not already part of the set.
    pub fn insert<T>(&mut self, elem: T) -> bool
    where
        T: Into<usize>,
    {
        let idx = self.idx(elem.into());
        let ret = self.data[idx.0] & (1 << idx.1) == 0;
        self.data[idx.0] |= 1 << idx.1;
        ret
    }

    pub fn remove<T>(&mut self, elem: T)
    where
        T: Into<usize>,
    {
        let idx = self.idx(elem.into());
        self.data[idx.0] &= !(1 << idx.1);
    }

    pub fn symm_diff(&self, other: impl Borrow<Self>) -> FiniteIntegerSet<U, N> {
        let other = other.borrow();
        let in_both = self & other;
        &(self | other) - &in_both
    }

    pub fn empty(&self) -> bool {
        !self.data.iter().any(|e| *e > 0)
    }

    pub fn size(&self) -> usize {
        let mut ret = 0;
        for b in self.data.iter() {
            for idx in 0..8 {
                if b & 1 << idx > 0 {
                    ret += 1;
                }
            }
        }
        ret
    }

    pub fn len(&self) -> usize {
        self.size()
    }

    pub fn entries(&self) -> HashSet<U> {
        let mut res = HashSet::new();
        for (byte_idx, byte) in self.data.iter().enumerate() {
            for bit_idx in 0..8 {
                if (byte & (1 << bit_idx)) > 0 {
                    res.insert((byte_idx * 8 + bit_idx).into());
                }
            }
        }
        res
    }

    pub fn choose_random(&self, max: usize) -> FiniteIntegerSet<U, N> {
        let mut entries: Vec<_> = self
            .entries()
            .into_iter()
            .choose_multiple(&mut thread_rng(), max);
        entries.shuffle(&mut thread_rng());
        entries.into_iter().collect()
    }

    /// Get a subset with a maximum size of `n`.
    pub fn get_sub_set(&self, n: usize) -> FiniteIntegerSet<U, N> {
        let mut rng = thread_rng();
        let mut entries: Vec<_> = self.entries().into_iter().collect();
        entries.shuffle(&mut rng);
        entries.into_iter().take(n).collect()
    }

    #[allow(unused)]
    pub(crate) fn contains(&self, id: U) -> bool {
        self.entries().contains(&id)
    }
}

impl<U, const N: usize> PartialEq for FiniteIntegerSet<U, N>
where
    U: From<usize> + Eq + hash::Hash,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.max_val == other.max_val
    }
}

impl<U, const N: usize> Eq for FiniteIntegerSet<U, N> where U: From<usize> + Eq + hash::Hash {}

impl<U, const N: usize> FromIterator<U> for FiniteIntegerSet<U, N>
where
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
    usize: From<U>,
{
    fn from_iter<T: IntoIterator<Item = U>>(iter: T) -> Self {
        let mut map: FiniteIntegerSet<U, N> = Self::new();
        for v in iter {
            map.insert(v);
        }
        map
    }
}

impl<U, const N: usize> IntoIterator for FiniteIntegerSet<U, N>
where
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
    usize: From<U>,
{
    type Item = U;
    type IntoIter = hash_set::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries().into_iter()
    }
}

impl<U, T, const N: usize> std::ops::BitOr<T> for &FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    fn bitor(self, rhs: T) -> Self::Output {
        let rhs = rhs.borrow();
        let a = self.data.iter();
        let b = rhs.data.iter();

        let mut ret = self.clone();
        a.zip(b).zip(ret.data.iter_mut()).for_each(|e| {
            *e.1 = e.0 .0 | e.0 .1;
        });

        ret
    }
}

impl<U, T, const N: usize> std::ops::BitOr<T> for FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    fn bitor(self, rhs: T) -> Self::Output {
        &self | rhs.borrow()
    }
}

impl<U, T, const N: usize> std::ops::BitAnd<T> for &FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    fn bitand(self, rhs: T) -> Self::Output {
        let rhs = rhs.borrow();
        let a = self.data.iter();
        let b = rhs.data.iter();

        let mut ret = self.clone();
        a.zip(b).zip(ret.data.iter_mut()).for_each(|e| {
            *e.1 = e.0 .0 & e.0 .1;
        });

        ret
    }
}

impl<U, T, const N: usize> std::ops::BitAnd<T> for FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = Self;

    fn bitand(self, rhs: T) -> Self::Output {
        &self & rhs.borrow()
    }
}

impl<U, T, const N: usize> std::ops::Add<T> for &FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: T) -> Self::Output {
        self | rhs.borrow()
    }
}

impl<U, T, const N: usize> std::ops::Add<T> for FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: T) -> Self::Output {
        self | rhs.borrow()
    }
}

impl<U, T, const N: usize> std::ops::Sub<T> for &FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    fn sub(self, rhs: T) -> Self::Output {
        let rhs = rhs.borrow();
        let a = self.data.iter();
        let b = rhs.data.iter();

        let mut ret = self.clone();
        a.zip(b).zip(ret.data.iter_mut()).for_each(|e| {
            *e.1 = e.0 .0 & !e.0 .1;
        });

        ret
    }
}

impl<U, T, const N: usize> std::ops::Sub<T> for FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    type Output = FiniteIntegerSet<U, N>;

    fn sub(self, rhs: T) -> Self::Output {
        &self - rhs.borrow()
    }
}

impl<U, T, const N: usize> std::ops::SubAssign<T> for &mut FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash,
{
    fn sub_assign(&mut self, rhs: T) {
        let rhs = rhs.borrow();
        let a = self.data.iter_mut();
        let b = rhs.data.iter();

        a.zip(b).for_each(|e| {
            *e.0 &= !e.1;
        });
    }
}

impl<U, T, const N: usize> std::ops::SubAssign<T> for FiniteIntegerSet<U, N>
where
    T: Borrow<FiniteIntegerSet<U, N>>,
    U: From<usize> + Eq + hash::Hash + Clone + fmt::Debug,
{
    fn sub_assign(&mut self, rhs: T) {
        let rhs = rhs.borrow();
        let a = self.data.iter_mut();
        let b = rhs.data.iter();

        a.zip(b).for_each(|e| {
            *e.0 &= !e.1;
        });
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use rand::{prelude::IteratorRandom, thread_rng};

    use super::FiniteIntegerSet;
    const SET32_SIZE: usize = 32;

    macro_rules! set32 {
        ($($elem:literal),*) => {
            {
                #[allow(unused_mut)]
                let mut s = FiniteIntegerSet::<usize, SET32_SIZE>::new();
                $(
                    s.insert($elem);
                )*
                s
            }
        };
    }

    #[test]
    fn insert() {
        let mut s0 = set32!();
        assert_eq!(s0.size(), 0);
        assert!(s0.empty());
        s0.insert(1usize);
        assert!(!s0.empty());
        assert_eq!(s0.size(), 1);
        s0.insert(2usize);
        assert_eq!(s0.size(), 2);
        s0.insert(2usize);
        assert_eq!(s0.size(), 2);
    }

    #[test]
    fn remove() {
        let mut s0 = set32!();
        s0.insert(1usize);
        s0.insert(2usize);
        assert_eq!(s0.size(), 2);
        s0.remove(1usize);
        assert_eq!(s0.size(), 1);
    }

    #[test]
    fn entries() {
        let mut set = FiniteIntegerSet::<usize, 100000>::new();
        let elems: HashSet<usize> = (0usize..10000usize)
            .choose_multiple(&mut thread_rng(), 100)
            .into_iter()
            .collect();
        for e in elems.iter() {
            set.insert(*e);
        }
        let elems_in_set = set.entries();
        assert_eq!(elems_in_set, elems);
    }

    #[test]
    fn and() {
        let s0 = set32!(1usize, 2usize);

        let mut s1 = s0.clone();
        let res = &s0 & &s1;
        assert_eq!(res, set32!(1usize, 2usize));

        s1.remove(2usize);
        let res = &s0 & &s1;
        assert_eq!(res, set32!(1usize));
    }

    #[test]
    fn or() {
        let s0 = set32!(1usize, 2usize);

        let mut s1 = s0.clone();
        s1.insert(3usize);

        let res = &s0 | &s1;
        assert_eq!(res, set32!(1usize, 2usize, 3usize));

        s1.remove(2usize);
        let res = &s0 | &s1;
        assert_eq!(res, set32!(1usize, 2usize, 3usize));

        s1.remove(3usize);
        let res = &s0 | &s1;
        assert_eq!(res, set32!(1usize, 2usize));
    }

    #[test]
    fn add() {
        let s0 = set32!(1usize, 2usize);
        let res = &s0 + &s0;
        assert_eq!(res, set32!(1usize, 2usize));

        let s0 = set32!(1usize, 2usize);
        let s1 = set32!(2usize, 3usize);
        let res = &s0 + &s1;
        assert_eq!(res, set32!(1usize, 2usize, 3usize));
    }

    #[test]
    fn sub() {
        let s0 = set32!(1usize, 2usize);
        let s1 = s0.clone();
        let res = &s0 - &s1;
        assert_eq!(res, set32!());

        let mut s1 = s0.clone();
        s1.remove(2usize);
        let res = &s0 - &s1;
        assert_eq!(res, set32!(2usize));
    }

    #[test]
    fn sub_assign() {
        let s0 = set32!(1usize, 2usize);
        let s1 = s0.clone();
        let res = &s0 - &s1;
        assert_eq!(res, set32!());

        let mut s1 = set32!(1usize, 2usize, 3usize, 10usize);
        s1 -= &s0;

        assert_eq!(s1, set32!(3usize, 10usize));
    }

    #[test]
    fn sym_diff() {
        let s0 = set32!(1usize, 2usize, 12usize, 13usize);
        let s1 = set32!(1usize, 2usize, 8usize, 12usize, 13usize);
        assert_eq!(s0.symm_diff(&s1), set32!(8usize));
    }
}
