# wsus-protocol fixtures

PROVENANCE: every file here is HAND-WRITTEN FROM THE SPECIFICATION
(MS-WUSP 38.0 WSDL appendices 6.1 to 6.3, MS-WSUSSS 17.0 WSDL appendices 6.1
and 6.2, and the fault descriptions in MS-WUSP 2.2.2.4 / MS-WSUSSS 2.2.9).
NONE of them was captured from a real WSUS server or Windows client. They
prove that the codecs implement the specified shapes; they do not prove
interoperability. Values (GUIDs, cookies, digests) are invented.

Files named `*_alt_prefix*` deliberately use unusual namespace prefixes and a
different default-namespace layout than the encoder produces.

Fragment fixtures (`fragment_core.txt`, `fragment_extended.txt`) follow
MS-WUSP 3.1.1.1 ("Metadata Table"): Core is the concatenation of
UpdateIdentity, Properties (reduced attributes), Relationships and
ApplicabilityRules; Extended is Properties (remaining attributes), Files and
HandlerSpecificData with no UpdateIdentity; namespace declarations removed;
elements of the Base/Msi/WindowsDriver applicability namespaces prefixed
`b.`, `m.`, `d.`. The spec says these are "not well-formed XML". Values are
invented; this is spec-derived, not captured.

`applicability_rules_core.txt` and `applicability_rules_strict.xml` are
hand-written from the element and attribute shapes the stored real catalog
uses (inventory, "Applicability rules"): invented ids, one of nearly every
operator, a `RegKeyLoop`, unsupported operators. `applicability_facts_sample.json`
is a hand-written snapshot in the format `scripts/wsus/collect-facts.ps1`
writes (the `RecordedFacts` loader tests parse it); it is NOT collected from a
machine.
