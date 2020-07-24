use std::convert::TryFrom;
use std::num::NonZeroUsize;
use std::ops;
use std::slice::SliceIndex;

/// Non empty vector, ensure non empty by construction.
/// Inherits `Vec`'s methods through `Deref` trait, not implement `DerefMut`.
/// Overridden these methods:
/// * `len` returns `NonZeroUsize` and `is_empty` always returns `false`.
/// * `first(_mut)`, `last(_mut)`, `split_first(_mut)`, `split_last(_mut)` don't return `Option`.
/// * `pop` returns `None` if there is only one element in it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    #[inline]
    pub fn new(vec: Vec<T>) -> Option<NonEmpty<T>> {
        if vec.is_empty() {
            None
        } else {
            Some(NonEmpty(vec))
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.0.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *const T {
        self.0.as_mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> NonZeroUsize {
        unsafe { NonZeroUsize::new_unchecked(self.0.len()) }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[inline]
    pub fn first(&self) -> &T {
        unsafe { self.0.get_unchecked(0) }
    }

    #[inline]
    pub fn first_mut(&mut self) -> &mut T {
        unsafe { self.0.get_unchecked_mut(0) }
    }

    #[inline]
    pub fn last(&self) -> &T {
        let i = self.len().get() - 1;
        unsafe { self.0.get_unchecked(i) }
    }

    #[inline]
    pub fn last_mut(&mut self) -> &mut T {
        let i = self.len().get() - 1;
        unsafe { self.0.get_unchecked_mut(i) }
    }

    #[inline]
    pub fn split_first(&self) -> (&T, &[T]) {
        (&self[0], &self[1..])
    }

    #[inline]
    pub fn split_first_mut(&mut self) -> (&mut T, &mut [T]) {
        let split = self.0.split_at_mut(1);
        (&mut split.0[0], split.1)
    }

    #[inline]
    pub fn split_last(&self) -> (&T, &[T]) {
        let len = self.len().get();
        (&self[len - 1], &self[..(len - 1)])
    }

    #[inline]
    pub fn split_last_mut(&mut self) -> (&mut T, &mut [T]) {
        let i = self.len().get() - 1;
        let split = self.0.split_at_mut(i);
        (&mut split.1[0], split.0)
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.0.len() <= 1 {
            None
        } else {
            self.0.pop()
        }
    }

    #[inline]
    pub fn push(&mut self, v: T) {
        self.0.push(v)
    }
}

impl<T> From<(Vec<T>, T)> for NonEmpty<T> {
    fn from((mut xs, x): (Vec<T>, T)) -> NonEmpty<T> {
        xs.push(x);
        NonEmpty(xs)
    }
}

impl<T> From<(T, Vec<T>)> for NonEmpty<T> {
    fn from((x, mut xs): (T, Vec<T>)) -> NonEmpty<T> {
        xs.insert(0, x);
        NonEmpty(xs)
    }
}

impl<T> From<T> for NonEmpty<T> {
    fn from(x: T) -> NonEmpty<T> {
        NonEmpty(vec![x])
    }
}

impl<T> From<NonEmpty<T>> for Vec<T> {
    fn from(v: NonEmpty<T>) -> Self {
        v.0
    }
}

#[derive(Debug, PartialEq)]
pub struct EmptyError;

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = EmptyError;
    fn try_from(xs: Vec<T>) -> Result<Self, Self::Error> {
        if xs.is_empty() {
            Err(EmptyError)
        } else {
            Ok(NonEmpty(xs))
        }
    }
}

impl<T> ops::Deref for NonEmpty<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.0.deref()
    }
}

/*
// unsafe
impl<T> ops::DerefMut for NonEmpty<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.0.deref_mut()
    }
}

impl<T> AsMut<Vec<T>> for NonEmpty<T> {
    fn as_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }
}
*/

impl<T> AsRef<[T]> for NonEmpty<T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T> AsMut<[T]> for NonEmpty<T> {
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut()
    }
}

impl<T> AsRef<Vec<T>> for NonEmpty<T> {
    fn as_ref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T, I: SliceIndex<[T]>> ops::Index<I> for NonEmpty<T> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        ops::Index::index(self.as_slice(), index)
    }
}
impl<T, I: SliceIndex<[T]>> ops::IndexMut<I> for NonEmpty<T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        ops::IndexMut::index_mut(self.as_mut_slice(), index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        // From
        let mut list: NonEmpty<i32> = (vec![1, 2], 3).into();
        assert_eq!(list, (1, vec![2, 3]).into());
        assert_eq!(&*list, &[1, 2, 3]);

        // Index
        list[0] = 2;
        assert_eq!(list[0], 2);
        list[0] = 1;
        assert_eq!(list[0], 1);

        // slice methods
        assert_eq!(list.len().get(), 3);
        assert_eq!(list.as_slice(), &[1, 2, 3]);

        // TryFrom
        assert_eq!(<NonEmpty<i32>>::try_from(vec![]).ok(), None);
        assert_eq!(
            &*<NonEmpty<i32>>::try_from(vec![1, 2, 3]).unwrap(),
            &[1, 2, 3]
        );

        // Iterator
        assert_eq!(
            list.iter().map(|n| n * 2).collect::<Vec<_>>(),
            vec![2, 4, 6]
        );
    }
}
