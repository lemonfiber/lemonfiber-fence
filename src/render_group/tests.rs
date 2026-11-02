use std::io::{Error, ErrorKind};

use super::{asked, Entry, DEVICES};

fn holding<'a>(entries: &'a [(&'a str, u32)]) -> impl Fn(&str) -> std::io::Result<Vec<Entry>> + 'a {
    move |path| {
        assert_eq!(path, DEVICES);
        Ok(entries
            .iter()
            .map(|(name, group)| ((*name).to_owned(), *group))
            .collect())
    }
}

#[test]
fn the_group_owning_the_render_devices_is_answered_and_the_card_is_passed_over() {
    assert_eq!(
        asked(&holding(&[
            ("card0", 44),
            ("renderD128", 109),
            ("renderD129", 109)
        ])),
        Ok(Some(109))
    );
}

#[test]
fn a_host_without_render_devices_answers_nothing() {
    assert_eq!(asked(&|_| Err(Error::from(ErrorKind::NotFound))), Ok(None));
    assert_eq!(asked(&holding(&[("card0", 44), ("by-path", 0)])), Ok(None));
    assert_eq!(asked(&holding(&[])), Ok(None));
}

#[test]
fn render_devices_owned_by_two_groups_are_refused_naming_each() {
    assert_eq!(
        asked(&holding(&[("renderD128", 109), ("renderD129", 110)])),
        Err(
            "the render devices under /dev/dri are owned by more than one group: 109, 110"
                .to_owned()
        )
    );
}

#[test]
fn a_device_directory_that_cannot_be_read_is_refused_naming_it() {
    assert!(asked(&|_| Err(Error::from(ErrorKind::PermissionDenied)))
        .is_err_and(|why| why.starts_with("/dev/dri could not be read")));
}

#[test]
fn the_listing_reads_each_entry_with_the_group_owning_it() {
    let dir = std::env::temp_dir().join(format!("fence-render-group-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(std::fs::create_dir_all(&dir).is_ok());
    assert!(std::fs::write(dir.join("renderD128"), "").is_ok());
    let listed = super::listed(&dir.display().to_string());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(listed.is_ok_and(|entries| entries.len() == 1
        && entries
            .first()
            .is_some_and(|(name, _)| name == "renderD128")));
}
