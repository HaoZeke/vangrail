use std::collections::HashMap;

use magnus::{function, method, prelude::*, Error, Ruby};

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
    let mut hash: u32 = 2_166_136_261;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
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

        let mut counts: HashMap<String, i64> = HashMap::new();
        for word in &words {
            bump(&mut counts, word);
        }
        for pair in words.windows(2) {
            let key = format!("{} {}", pair[0], pair[1]);
            bump(&mut counts, &key);
        }
        let chars: Vec<char> = normalised.chars().collect();
        if chars.len() > 4 {
            let mut i = 0;
            while i <= chars.len() - 4 {
                let gram: String = chars[i..i + 4].iter().collect();
                let key = format!("c:{gram}");
                bump(&mut counts, &key);
                i += stride;
            }
        }

        let mut acc = HashMap::<usize, f64>::new();
        for (feature, count) in counts {
            let n = count.min(3) as f64;
            let index = fnv1a(feature.as_bytes()) as usize % buckets;
            *acc.entry(index).or_insert(0.0) += n;
        }

        let mut score = bias;
        for (index, value) in acc {
            score += self.weights[index] * value;
        }
        Ok(score)
    }
}

fn bump(counts: &mut HashMap<String, i64>, key: &str) {
    *counts.entry(key.to_string()).or_insert(0) += 1;
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
