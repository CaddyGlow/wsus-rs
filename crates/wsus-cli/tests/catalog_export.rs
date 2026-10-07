//! Host export checks; native wsusutil acceptance requires a separate guest gate.

use std::{fs, io::Cursor};

use wsus_cli::{
    admin::{self, Admin},
    config::Config,
    export::catalog_export,
};

fn environment() -> (tempfile::TempDir, Admin) {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::defaults_in(dir.path());
    let admin = Admin::open(&config).unwrap();
    admin::source_add(&admin, "upstream", "import", "").unwrap();
    let input = dir.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("detectoid.xml"), concat!(
        "<Update xmlns=\"http://schemas.microsoft.com/msus/2002/12/Update\">",
        "<UpdateIdentity UpdateID=\"00000000-0000-0000-0000-000000000001\" RevisionNumber=\"1\"/>",
            "<Properties UpdateType=\"Detectoid\"/><Relationships/>",
            "<LocalizedPropertiesCollection/><ApplicabilityRules/>",
        "</Update>"
    )).unwrap();
    wsus_cli::import::catalog_import(&admin, None, &input, None, false).unwrap();
    (dir, admin)
}

#[test]
fn exports_native_members_without_changing_active_generation() {
    let (dir, admin) = environment();
    let source = admin.catalog.source_by_name("upstream").unwrap().unwrap();
    let generation = admin.catalog.active_generation(source.id).unwrap();
    let out = dir.path().join("metadata.cab");
    let result = catalog_export(&admin, None, &out, None).unwrap();
    assert!(result.ok);
    assert_eq!(
        admin.catalog.active_generation(source.id).unwrap(),
        generation
    );
    let mut cabinet = cabinet::Cabinet::new(Cursor::new(fs::read(&out).unwrap())).unwrap();
    let package = cabinet.read_file_bytes("package.xml", 1024 * 1024).unwrap();
    let metadata = cabinet
        .read_file_bytes("metadata.txt", 1024 * 1024)
        .unwrap();
    assert!(
        String::from_utf8(package)
            .unwrap()
            .contains("ExportPackage")
    );
    assert!(metadata.starts_with(b"00000000-0000-0000-0000-000000000001,00000001,"));
    assert!(metadata.ends_with(b"\r\n"));
}

#[test]
fn refuses_to_replace_an_existing_package() {
    let (dir, admin) = environment();
    let out = dir.path().join("metadata.cab");
    fs::write(&out, b"preserve existing export").unwrap();
    assert!(catalog_export(&admin, None, &out, None).is_err());
    assert_eq!(fs::read(out).unwrap(), b"preserve existing export");
}

#[test]
fn rejects_gzip_filename_instead_of_mislabeling_a_cabinet() {
    let (dir, admin) = environment();
    let out = dir.path().join("metadata.xml.gz");
    let error = catalog_export(&admin, None, &out, None).unwrap_err();
    assert!(error.to_string().contains(".cab"));
    assert!(!out.exists());
}
