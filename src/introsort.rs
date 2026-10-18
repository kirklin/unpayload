//! An unstable sort whose placement of equal elements is fully specified.
//!
//! Some patch formats are produced by tools that sort records with ties and
//! then derive data from the resulting order, so applying such a patch needs
//! the very same order. This is the introsort those tools are built with:
//! median-of-three pivots (ninther above 128 elements), partitions that keep
//! elements equal to the pivot on one side, a cut-off to insertion sort below
//! 24 elements, a bounded insertion sort after partitions that moved nothing,
//! and heap sort once the recursion depth reaches twice the base-2 logarithm
//! of the length.

pub(crate) fn sort_by<T: Clone>(v: &mut [T], less: impl Fn(&T, &T) -> bool) {
    let n = v.len();
    if n < 2 {
        return;
    }
    let depth = 2 * n.ilog2() as usize;
    introsort(v, 0, n, &less, depth, true);
}

const INSERTION_LIMIT: usize = 24;
const NINTHER_THRESHOLD: usize = 128;

fn introsort<T: Clone>(
    v: &mut [T],
    mut first: usize,
    mut last: usize,
    less: &impl Fn(&T, &T) -> bool,
    mut depth: usize,
    mut leftmost: bool,
) {
    loop {
        let len = last - first;
        match len {
            0 | 1 => return,
            2 => {
                if less(&v[last - 1], &v[first]) {
                    v.swap(first, last - 1);
                }
                return;
            }
            3 => return sort3(v, first, first + 1, last - 1, less),
            4 => return sort4(v, first, first + 1, first + 2, last - 1, less),
            5 => return sort5(v, [first, first + 1, first + 2, first + 3, last - 1], less),
            _ => {}
        }
        if len < INSERTION_LIMIT {
            if leftmost {
                insertion_sort(v, first, last, less);
            } else {
                insertion_sort_unguarded(v, first, last, less);
            }
            return;
        }
        if depth == 0 {
            heap_sort(v, first, last, less);
            return;
        }
        depth -= 1;
        let half = len / 2;
        if len > NINTHER_THRESHOLD {
            sort3(v, first, first + half, last - 1, less);
            sort3(v, first + 1, first + half - 1, last - 2, less);
            sort3(v, first + 2, first + half + 1, last - 3, less);
            sort3(v, first + half - 1, first + half, first + half + 1, less);
            v.swap(first, first + half);
        } else {
            sort3(v, first + half, first, last - 1, less);
        }
        if !leftmost && !less(&v[first - 1], &v[first]) {
            first = partition_equals_left(v, first, last, less);
            continue;
        }
        let (pivot, already_partitioned) = partition_equals_right(v, first, last, less);
        if already_partitioned {
            let left_sorted = insertion_sort_incomplete(v, first, pivot, less);
            if insertion_sort_incomplete(v, pivot + 1, last, less) {
                if left_sorted {
                    return;
                }
                last = pivot;
                continue;
            } else if left_sorted {
                first = pivot + 1;
                continue;
            }
        }
        introsort(v, first, pivot, less, depth, leftmost);
        leftmost = false;
        first = pivot + 1;
    }
}

fn sort3<T>(v: &mut [T], x: usize, y: usize, z: usize, less: &impl Fn(&T, &T) -> bool) {
    if !less(&v[y], &v[x]) {
        if !less(&v[z], &v[y]) {
            return;
        }
        v.swap(y, z);
        if less(&v[y], &v[x]) {
            v.swap(x, y);
        }
        return;
    }
    if less(&v[z], &v[y]) {
        v.swap(x, z);
        return;
    }
    v.swap(x, y);
    if less(&v[z], &v[y]) {
        v.swap(y, z);
    }
}

fn sort4<T>(v: &mut [T], a: usize, b: usize, c: usize, d: usize, less: &impl Fn(&T, &T) -> bool) {
    sort3(v, a, b, c, less);
    if less(&v[d], &v[c]) {
        v.swap(c, d);
        if less(&v[c], &v[b]) {
            v.swap(b, c);
            if less(&v[b], &v[a]) {
                v.swap(a, b);
            }
        }
    }
}

fn sort5<T>(v: &mut [T], [a, b, c, d, e]: [usize; 5], less: &impl Fn(&T, &T) -> bool) {
    sort4(v, a, b, c, d, less);
    if less(&v[e], &v[d]) {
        v.swap(d, e);
        if less(&v[d], &v[c]) {
            v.swap(c, d);
            if less(&v[c], &v[b]) {
                v.swap(b, c);
                if less(&v[b], &v[a]) {
                    v.swap(a, b);
                }
            }
        }
    }
}

fn insertion_sort<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool) {
    for i in first + 1..last {
        if less(&v[i], &v[i - 1]) {
            let t = v[i].clone();
            let mut j = i;
            let mut k = i - 1;
            loop {
                v[j] = v[k].clone();
                j = k;
                if j == first {
                    break;
                }
                k -= 1;
                if !less(&t, &v[k]) {
                    break;
                }
            }
            v[j] = t;
        }
    }
}

/// Insertion sort for a range whose predecessor is no greater than any of its
/// elements, which bounds the inner loop.
fn insertion_sort_unguarded<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool) {
    for i in first + 1..last {
        if less(&v[i], &v[i - 1]) {
            let t = v[i].clone();
            let mut j = i;
            let mut k = i - 1;
            loop {
                v[j] = v[k].clone();
                j = k;
                k -= 1;
                if !less(&t, &v[k]) {
                    break;
                }
            }
            v[j] = t;
        }
    }
}

/// Insertion sort that gives up after moving eight elements; returns whether
/// the range ended up sorted.
fn insertion_sort_incomplete<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool) -> bool {
    match last - first {
        0 | 1 => return true,
        2 => {
            if less(&v[last - 1], &v[first]) {
                v.swap(first, last - 1);
            }
            return true;
        }
        3 => {
            sort3(v, first, first + 1, last - 1, less);
            return true;
        }
        4 => {
            sort4(v, first, first + 1, first + 2, last - 1, less);
            return true;
        }
        5 => {
            sort5(v, [first, first + 1, first + 2, first + 3, last - 1], less);
            return true;
        }
        _ => {}
    }
    let mut j = first + 2;
    sort3(v, first, first + 1, j, less);
    let mut moved = 0;
    let mut i = j + 1;
    while i != last {
        if less(&v[i], &v[j]) {
            let t = v[i].clone();
            let mut k = j;
            j = i;
            loop {
                v[j] = v[k].clone();
                j = k;
                if j == first {
                    break;
                }
                k -= 1;
                if !less(&t, &v[k]) {
                    break;
                }
            }
            v[j] = t;
            moved += 1;
            if moved == 8 {
                return i + 1 == last;
            }
        }
        j = i;
        i += 1;
    }
    true
}

/// Partitions around `v[first]`, putting equal elements to its right. Returns
/// the pivot position and whether nothing had to be swapped.
fn partition_equals_right<T: Clone>(
    v: &mut [T],
    begin: usize,
    end: usize,
    less: &impl Fn(&T, &T) -> bool,
) -> (usize, bool) {
    let pivot = v[begin].clone();
    let mut first = begin;
    loop {
        first += 1;
        if !less(&v[first], &pivot) {
            break;
        }
    }
    let mut last = end;
    if begin == first - 1 {
        while first < last {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    } else {
        loop {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    }
    let already_partitioned = first >= last;
    while first < last {
        v.swap(first, last);
        loop {
            first += 1;
            if !less(&v[first], &pivot) {
                break;
            }
        }
        loop {
            last -= 1;
            if less(&v[last], &pivot) {
                break;
            }
        }
    }
    let pivot_pos = first - 1;
    if begin != pivot_pos {
        v[begin] = v[pivot_pos].clone();
    }
    v[pivot_pos] = pivot;
    (pivot_pos, already_partitioned)
}

/// Partitions around `v[first]`, putting equal elements to its left. Returns
/// the position after the pivot.
fn partition_equals_left<T: Clone>(v: &mut [T], begin: usize, end: usize, less: &impl Fn(&T, &T) -> bool) -> usize {
    let pivot = v[begin].clone();
    let mut first = begin;
    let mut last = end;
    if less(&pivot, &v[last - 1]) {
        loop {
            first += 1;
            if less(&pivot, &v[first]) {
                break;
            }
        }
    } else {
        loop {
            first += 1;
            if !(first < last && !less(&pivot, &v[first])) {
                break;
            }
        }
    }
    if first < last {
        loop {
            last -= 1;
            if !less(&pivot, &v[last]) {
                break;
            }
        }
    }
    while first < last {
        v.swap(first, last);
        loop {
            first += 1;
            if less(&pivot, &v[first]) {
                break;
            }
        }
        loop {
            last -= 1;
            if !less(&pivot, &v[last]) {
                break;
            }
        }
    }
    let pivot_pos = first - 1;
    if begin != pivot_pos {
        v[begin] = v[pivot_pos].clone();
    }
    v[pivot_pos] = pivot;
    first
}

fn heap_sort<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool) {
    let len = last - first;
    if len > 1 {
        for start in (0..=(len - 2) / 2).rev() {
            sift_down(v, first, less, len, first + start);
        }
    }
    let mut end = last;
    let mut n = len;
    while n > 1 {
        pop_heap(v, first, end, less, n);
        end -= 1;
        n -= 1;
    }
}

fn sift_down<T: Clone>(v: &mut [T], first: usize, less: &impl Fn(&T, &T) -> bool, len: usize, mut start: usize) {
    let mut child = start - first;
    if len < 2 || (len - 2) / 2 < child {
        return;
    }
    child = 2 * child + 1;
    let mut child_i = first + child;
    if child + 1 < len && less(&v[child_i], &v[child_i + 1]) {
        child_i += 1;
        child += 1;
    }
    if less(&v[child_i], &v[start]) {
        return;
    }
    let top = v[start].clone();
    loop {
        v[start] = v[child_i].clone();
        start = child_i;
        if (len - 2) / 2 < child {
            break;
        }
        child = 2 * child + 1;
        child_i = first + child;
        if child + 1 < len && less(&v[child_i], &v[child_i + 1]) {
            child_i += 1;
            child += 1;
        }
        if less(&v[child_i], &top) {
            break;
        }
    }
    v[start] = top;
}

fn pop_heap<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool, len: usize) {
    if len < 2 {
        return;
    }
    let top = v[first].clone();
    let hole = floyd_sift_down(v, first, less, len);
    let last = last - 1;
    if hole == last {
        v[hole] = top;
    } else {
        v[hole] = v[last].clone();
        v[last] = top;
        sift_up(v, first, hole + 1, less, hole + 1 - first);
    }
}

fn floyd_sift_down<T: Clone>(v: &mut [T], first: usize, less: &impl Fn(&T, &T) -> bool, len: usize) -> usize {
    let mut hole = first;
    let mut child_i = first;
    let mut child = 0;
    loop {
        child_i += child + 1;
        child = 2 * child + 1;
        if child + 1 < len && less(&v[child_i], &v[child_i + 1]) {
            child_i += 1;
            child += 1;
        }
        v[hole] = v[child_i].clone();
        hole = child_i;
        if child > (len - 2) / 2 {
            return hole;
        }
    }
}

fn sift_up<T: Clone>(v: &mut [T], first: usize, last: usize, less: &impl Fn(&T, &T) -> bool, len: usize) {
    if len < 2 {
        return;
    }
    let mut len = (len - 2) / 2;
    let mut parent = first + len;
    let mut last = last - 1;
    if less(&v[parent], &v[last]) {
        let t = v[last].clone();
        loop {
            v[last] = v[parent].clone();
            last = parent;
            if len == 0 {
                break;
            }
            len = (len - 1) / 2;
            parent = first + len;
            if !less(&v[parent], &t) {
                break;
            }
        }
        v[last] = t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u32, key: impl Fn(u32) -> u32, sort: impl FnOnce(&mut [(u32, u32)])) -> Vec<u32> {
        let mut items: Vec<(u32, u32)> = (0..n).map(|id| (key(id), id)).collect();
        sort(&mut items);
        assert!(items.windows(2).all(|w| w[0].0 <= w[1].0));
        items.into_iter().map(|(_, id)| id).collect()
    }

    fn by_key(items: &mut [(u32, u32)]) {
        sort_by(items, |a, b| a.0 < b.0);
    }

    #[test]
    fn places_equal_elements_deterministically() {
        let key = |i: u32| (i * 7 + i / 5) % 3;
        assert_eq!(ids(6, key, by_key), [0, 3, 5, 1, 4, 2]);
        assert_eq!(
            ids(30, key, by_key),
            [
                0, 3, 5, 8, 10, 13, 15, 18, 20, 23, 28, 25, 16, 9, 11, 14, 6, 19, 21, 24, 4, 26, 1, 29, 2, 7, 12, 17,
                22, 27
            ]
        );
        assert_eq!(
            ids(130, key, by_key),
            [
                53, 128, 125, 3, 123, 5, 120, 118, 8, 115, 10, 113, 110, 13, 108, 15, 105, 103, 18, 100, 20, 98, 95,
                23, 93, 25, 90, 88, 28, 85, 30, 83, 80, 33, 78, 35, 75, 73, 38, 70, 40, 68, 0, 43, 65, 45, 63, 60, 48,
                58, 50, 55, 1, 104, 54, 51, 56, 64, 49, 59, 126, 61, 66, 46, 44, 124, 4, 121, 41, 69, 39, 71, 6, 119,
                74, 36, 76, 116, 34, 79, 9, 81, 114, 31, 84, 29, 86, 11, 111, 89, 26, 91, 109, 24, 94, 14, 96, 106, 21,
                99, 19, 101, 16, 129, 17, 102, 97, 107, 22, 92, 12, 27, 112, 87, 82, 32, 77, 117, 7, 37, 72, 67, 122,
                2, 42, 62, 47, 127, 57, 52
            ]
        );
    }

    #[test]
    fn heap_sort_places_equal_elements_deterministically() {
        let heap = |items: &mut [(u32, u32)]| {
            let len = items.len();
            heap_sort(items, 0, len, &|a: &(u32, u32), b: &(u32, u32)| a.0 < b.0);
        };
        assert_eq!(
            ids(40, |i| (i * 5) % 4, heap),
            [
                4, 36, 8, 32, 12, 16, 0, 24, 20, 28, 13, 25, 5, 21, 9, 29, 17, 33, 37, 1, 30, 6, 26, 2, 10, 22, 14, 18,
                38, 34, 27, 11, 23, 19, 39, 35, 3, 7, 15, 31
            ]
        );
    }

    #[test]
    fn sorts_large_inputs() {
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut values: Vec<u64> = (0..100_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state % 1000
            })
            .collect();
        let mut expected = values.clone();
        expected.sort_unstable();
        sort_by(&mut values, |a, b| a < b);
        assert_eq!(values, expected);
    }
}
