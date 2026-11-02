//! The group that owns the host's render devices, read from the `/dev/dri` lemonfiber
//! mounts into the container read-only.
//!
//! lemonfiber runs `fence render-group` once with the host's `/dev/dri` mounted and every
//! capability dropped, to learn the group it adds to a service taking `render`. What is
//! printed is that group's id, or nothing where the host has no render device. Where the
//! host's render devices are owned by more than one group, no one group gives a service
//! all of them, so nothing is answered and the run fails, naming each.

use std::collections::BTreeSet;
use std::io::ErrorKind;

/// Where the host's render devices are mounted.
pub const DEVICES: &str = "/dev/dri";

/// One entry under [`DEVICES`]: its name, and the id of the group that owns it.
pub type Entry = (String, u32);

/// What the name of a render device begins with, as the kernel names one.
const RENDER: &str = "renderD";

/// The group owning every render device `listing` finds under [`DEVICES`], as each
/// entry's name and the id of the group that owns it, or nothing where there is no
/// [`DEVICES`] or no render device in it.
///
/// # Errors
///
/// Where [`DEVICES`] is there and cannot be read, or its render devices are owned by more
/// than one group.
pub fn asked(listing: &dyn Fn(&str) -> std::io::Result<Vec<Entry>>) -> Result<Option<u32>, String> {
    let entries = match listing(DEVICES) {
        Ok(entries) => entries,
        Err(why) if why.kind() == ErrorKind::NotFound => return Ok(None),
        Err(why) => return Err(format!("{DEVICES} could not be read: {why}")),
    };
    let owners: BTreeSet<u32> = entries
        .into_iter()
        .filter(|(name, _)| name.starts_with(RENDER))
        .map(|(_, group)| group)
        .collect();
    let mut owning = owners.iter();
    match (owning.next(), owning.next()) {
        (None, _) => Ok(None),
        (Some(group), None) => Ok(Some(*group)),
        (Some(_), Some(_)) => Err(format!(
            "the render devices under {DEVICES} are owned by more than one group: {}",
            owners
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Each entry under `path`, by name, with the id of the group that owns it.
///
/// # Errors
///
/// Where `path` or an entry of it cannot be read.
pub fn listed(path: &str) -> std::io::Result<Vec<Entry>> {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::read_dir(path)?
        .map(|entry| {
            let entry = entry?;
            let group = entry.metadata()?.gid();
            Ok((entry.file_name().to_string_lossy().into_owned(), group))
        })
        .collect()
}

#[cfg(test)]
mod tests;
