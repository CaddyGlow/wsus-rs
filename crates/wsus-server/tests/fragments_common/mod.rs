#![allow(dead_code)]
//! Hand-written whole update document in the shape MS-WSUSSS `GetUpdateData` delivers.
//!
//! PROVENANCE: written from the specification text, not captured from a WSUS server.
//! Identifiers and digests are invented. It exercises the Base, Msi and WindowsDriver
//! applicability namespaces, an unlisted handler namespace, localized properties in two
//! languages, a prerequisite and bundle CNF, supersedence, files with an additional digest
//! and unknown top-level elements.
use uuid::Uuid;

pub const BASE_NS: &str = "http://schemas.microsoft.com/msus/2002/12/BaseApplicabilityRules";
pub const MSI_NS: &str = "http://schemas.microsoft.com/msus/2002/12/MsiApplicabilityRules";
pub const DRV_NS: &str = "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/WindowsDriver";
pub const CBS_NS: &str =
    "http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CbsApplicability";

pub fn whole_doc(n: u128, rev: u32) -> String {
    let id = Uuid::from_u128(n).hyphenated();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Update xmlns="http://schemas.microsoft.com/msus/2002/12/Update" xmlns:b="{BASE_NS}" xmlns:m="{MSI_NS}" xmlns:d="{DRV_NS}" xmlns:cbs="{CBS_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <UpdateIdentity UpdateID="{id}" RevisionNumber="{rev}"/>
  <Properties DefaultPropertiesLanguage="en" UpdateType="Software" ExplicitlyDeployable="true" AutoSelectOnWebSites="true" OSUpgrade="false" EulaID="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" MaxDownloadSize="1234" PublicationState="Published" FutureAttribute="a &amp; &quot;b&quot;"><SupportUrl>http://example.invalid/?a=1&amp;b=2</SupportUrl></Properties>
  <LocalizedPropertiesCollection>
    <LocalizedProperties><Language>en</Language><Title>Example update</Title><Description>Fixes &lt;things&gt;.</Description></LocalizedProperties>
    <LocalizedProperties><Language>de</Language><Title>Beispiel</Title></LocalizedProperties>
  </LocalizedPropertiesCollection>
  <Relationships>
    <Prerequisites>
      <UpdateIdentity UpdateID="22222222-2222-4222-8222-222222222222"/>
      <AtLeastOne IsCategory="true">
        <UpdateIdentity UpdateID="33333333-3333-4333-8333-333333333333"/>
        <UpdateIdentity UpdateID="44444444-4444-4444-8444-444444444444"/>
      </AtLeastOne>
    </Prerequisites>
    <BundledUpdates>
      <UpdateIdentity UpdateID="55555555-5555-4555-8555-555555555555" RevisionNumber="1"/>
    </BundledUpdates>
    <SupersededUpdates>
      <UpdateIdentity UpdateID="88888888-8888-4888-8888-888888888888"/>
    </SupersededUpdates>
  </Relationships>
  <ApplicabilityRules>
    <IsInstalled><b:And><b:RegSzToVersion Key="HKLM\SOFTWARE\X" Comparison="GreaterThan" Data="1.0"/><b:Not><m:MsiProductInstalled ProductCode="{{00000000-0000-0000-0000-000000000000}}"/></b:Not></b:And></IsInstalled>
    <IsInstallable><d:DriverCheck HardwareId="PCI\VEN_8086" xsi:type="d:Special"/><cbs:CbsPackage Id="Package_for_X"/></IsInstallable>
    <IsSuperseded><b:False/></IsSuperseded>
  </ApplicabilityRules>
  <Files>
    <File FileName="update.cab" Size="13" Modified="2024-01-01T00:00:00.000" Digest="AAECAwQFBgcICQoLDA0ODxAREhM=" DigestAlgorithm="SHA1" PatchingType="None">
      <AdditionalDigest Algorithm="SHA256">AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=</AdditionalDigest>
    </File>
  </Files>
  <HandlerSpecificData xsi:type="cbs:Handler"><Thing a="1">text &amp; more</Thing></HandlerSpecificData>
  <FutureTopLevel Z="1"><X/></FutureTopLevel>
</Update>"#
    )
}
