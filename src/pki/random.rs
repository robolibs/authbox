use super::{PkiError, PkiResult};

pub(crate) fn fill_random(out: &mut [u8]) -> PkiResult<()> {
    getrandom::getrandom(out)
        .map_err(|err| PkiError::new(format!("random generation failed: {err}")))
}
