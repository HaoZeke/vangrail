use std::collections::HashMap;

use magnus::{function, method, prelude::*, Error, Ruby};

const FNV_OFFSET: u32 = 2_166_136_261;
const FNV_PRIME: u32 = 16_777_619;

/// FNV-1a as `LinearModel.bucket`: process-stable, not `String#hash`.
fn bucket(feature: String, buckets: i64) -> Result<i64, Error> {
    let n = usize_arg(buckets, "buckets")?;
    if n == 0 {
        return Err(Error::new(
            exception_arg_error(),
            "buckets must be positive",
        ));
    }
    Ok((fnv1a(feature.as_bytes()) as usize % n) as i64)
}

fn fnv1a(bytes: &[u8]) -> u32 {
    fnv1a_from(FNV_OFFSET, bytes)
}

fn fnv1a_from(mut hash: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[magnus::wrap(class = "Vangrail::Native::Table")]
struct Table {
    weights: Vec<f64>,
}

impl Table {
    fn new(weights: Vec<f64>) -> Self {
        Self { weights }
    }

    /// Hashed bag + dot product. `words` are already stemmed; `normalised` is
    /// already NFKC-folded. Those stay in Ruby so train and serve cannot drift.
    fn score(
        &self,
        bias: f64,
        buckets: i64,
        stride: i64,
        words: Vec<String>,
        normalised: String,
    ) -> Result<f64, Error> {
        let buckets = usize_arg(buckets, "buckets")?;
        let stride = usize_arg(stride, "stride")?;
        if buckets == 0 || self.weights.len() != buckets {
            return Err(Error::new(
                exception_arg_error(),
                format!(
                    "weights.size ({}) != buckets ({buckets})",
                    self.weights.len()
                ),
            ));
        }
        if stride == 0 {
            return Err(Error::new(
                exception_arg_error(),
                "stride must be positive",
            ));
        }

        let mut acc = HashMap::<usize, f64>::new();
        let mut word_counts = HashMap::<&str, u8>::with_capacity(words.len());
        for word in &words {
            let count = word_counts.entry(word.as_str()).or_insert(0);
            if *count < 3 {
                *count += 1;
                add_bucket(&mut acc, fnv1a(word.as_bytes()) as usize % buckets);
            }
        }

        let mut pair_counts = HashMap::<(&str, &str), u8>::with_capacity(words.len());
        for pair in words.windows(2) {
            let key = (pair[0].as_str(), pair[1].as_str());
            let count = pair_counts.entry(key).or_insert(0);
            if *count < 3 {
                *count += 1;
                add_bucket(&mut acc, pair_bucket(key.0, key.1, buckets));
            }
        }

        let chars: Vec<char> = normalised.chars().collect();
        if chars.len() > 4 {
            let mut gram_counts = HashMap::<[char; 4], u8>::with_capacity(chars.len() / stride);
            for window in chars.windows(4).step_by(stride) {
                let gram = [window[0], window[1], window[2], window[3]];
                let count = gram_counts.entry(gram).or_insert(0);
                if *count < 3 {
                    *count += 1;
                    add_bucket(&mut acc, character_bucket(gram, buckets));
                }
            }
        }

        let mut score = bias;
        for (index, value) in acc {
            score += self.weights[index] * value;
        }
        Ok(score)
    }
}

fn add_bucket(acc: &mut HashMap<usize, f64>, index: usize) {
    *acc.entry(index).or_insert(0.0) += 1.0;
}

fn pair_bucket(left: &str, right: &str, buckets: usize) -> usize {
    let hash = fnv1a_from(FNV_OFFSET, left.as_bytes());
    let hash = fnv1a_from(hash, b" ");
    fnv1a_from(hash, right.as_bytes()) as usize % buckets
}

fn character_bucket(gram: [char; 4], buckets: usize) -> usize {
    let mut hash = fnv1a_from(FNV_OFFSET, b"c:");
    let mut buffer = [0_u8; 4];
    for character in gram {
        hash = fnv1a_from(hash, character.encode_utf8(&mut buffer).as_bytes());
    }
    hash as usize % buckets
}

fn exception_arg_error() -> magnus::ExceptionClass {
    Ruby::get().expect("not on a Ruby thread").exception_arg_error()
}

fn usize_arg(value: i64, name: &str) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| {
        Error::new(
            exception_arg_error(),
            format!("{name} must be a non-negative integer"),
        )
    })
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Vangrail")?.define_module("Native")?;
    module.define_singleton_method("bucket", function!(bucket, 2))?;

    let class = module.define_class("Table", ruby.class_object())?;
    class.define_singleton_method("new", function!(Table::new, 1))?;
    class.define_method("score", method!(Table::score, 5))?;
    Ok(())
}
