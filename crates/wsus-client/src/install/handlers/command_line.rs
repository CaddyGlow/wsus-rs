//! The `CommandLineInstallation` handler.
//!
//! Observed schema (stored real catalog, Extended fragments; see the
//! inventory section "Observed HandlerSpecificData"):
//!
//! ```xml
//! <ExtendedProperties Handler="http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation" ...>
//!   <InstallationBehavior [Impact="Minor"] [RebootBehavior="CanRequestReboot"] />
//! </ExtendedProperties>
//! <Files><File FileName="AM_Delta.exe" Size=".." Digest=".." DigestAlgorithm="SHA1">
//!   <AdditionalDigest Algorithm="SHA256">..</AdditionalDigest></File></Files>
//! <HandlerSpecificData type="cmd:CommandLineInstallation">
//!   <InstallCommand Program="AM_Delta.exe" [Arguments="WD /q"]
//!                   [RebootByDefault="false" DefaultResult="Failed"]>
//!     <ReturnCode Code="0" Result="Succeeded" [Reboot="false"] />
//!     [<ReturnCode Code="-2142207945" Result="Failed" | Result="Succeeded" Reboot="true" />]
//!   </InstallCommand>
//! </HandlerSpecificData>
//! ```
//!
//! Decisions that go beyond the observations (Implementation decisions,
//! Unverified):
//!
//! * `Program` is a file name, never a path; it must name the update's own
//!   payload file and is executed from the verified store, never looked up on
//!   `PATH`.
//! * `Arguments` are split on ASCII spaces into separate arguments (no quote
//!   handling); every token must be made of `[A-Za-z0-9/._=:-]` only (all
//!   observed values are `WD /q`, `/Store`, `/LastPackage`). Anything else
//!   makes the spec invalid and the step is refused.
//! * An exit code with no matching `ReturnCode` is `Failed` (the observed
//!   `DefaultResult` is always `Failed`; without the attribute the same fail
//!   closed reading is used). `RebootByDefault` is only honoured for
//!   `Succeeded`; it is `false` wherever it occurs.
//! * A `ReturnCode/@Reboot="true"` with `Result="Succeeded"` means success
//!   with a reboot required.
use super::HandlerError;
use serde::{Deserialize, Serialize};
use wsus_protocol::soap::xml::Element;

/// `ReturnCode/@Result`. Only the two observed values are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultClass {
    Succeeded,
    Failed,
}

impl ResultClass {
    fn parse(s: &str) -> Result<Self, HandlerError> {
        match s {
            "Succeeded" => Ok(Self::Succeeded),
            "Failed" => Ok(Self::Failed),
            other => Err(HandlerError::Invalid(format!(
                "unknown ReturnCode Result `{other}`"
            ))),
        }
    }
}

/// One `ReturnCode` child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnCodeRule {
    pub code: i32,
    pub result: ResultClass,
    /// `Reboot` attribute, when present.
    pub reboot: Option<bool>,
}

/// Classification of a process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClass {
    Success,
    /// Succeeded and a reboot is required.
    Reboot,
    Failed,
}

/// Result of mapping an exit code through a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub class: ExitClass,
    /// True when a `ReturnCode` matched; false when the default applied.
    pub matched: bool,
}

/// Typed `CommandLineInstallation` data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandLineSpec {
    /// `InstallCommand/@Program`.
    pub program: String,
    /// `InstallCommand/@Arguments`, verbatim.
    pub arguments: Option<String>,
    pub reboot_by_default: Option<bool>,
    pub default_result: Option<ResultClass>,
    pub return_codes: Vec<ReturnCodeRule>,
}

fn parse_bool(name: &str, v: &str) -> Result<bool, HandlerError> {
    match v {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(HandlerError::Invalid(format!("{name}=`{other}`"))),
    }
}

/// One argument token: conservative character set, no quoting, no shell
/// metacharacters.
fn token_ok(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 128
        && t.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'=' | b':' | b'-')
        })
}

impl CommandLineSpec {
    /// Parses a `HandlerSpecificData` element.
    pub fn from_element(el: &Element) -> Result<Self, HandlerError> {
        let bad = |m: String| HandlerError::Invalid(m);
        let ty = el.attr("type").unwrap_or("");
        if ty != "cmd:CommandLineInstallation" {
            return Err(bad(format!("HandlerSpecificData type `{ty}`")));
        }
        let mut commands = el.elements().filter(|c| c.name.local == "InstallCommand");
        let cmd = commands
            .next()
            .ok_or_else(|| bad("no InstallCommand".into()))?;
        if commands.next().is_some() {
            return Err(bad("more than one InstallCommand".into()));
        }
        let program = cmd
            .attr("Program")
            .ok_or_else(|| bad("InstallCommand without Program".into()))?
            .to_owned();
        let arguments = cmd.attr("Arguments").map(str::to_owned);
        let reboot_by_default = cmd
            .attr("RebootByDefault")
            .map(|v| parse_bool("RebootByDefault", v))
            .transpose()?;
        let default_result = cmd
            .attr("DefaultResult")
            .map(ResultClass::parse)
            .transpose()?;
        let mut return_codes = Vec::new();
        for rc in cmd.elements() {
            if rc.name.local != "ReturnCode" {
                return Err(bad(format!(
                    "unexpected element {} in InstallCommand",
                    rc.name
                )));
            }
            let code: i32 = rc
                .attr("Code")
                .ok_or_else(|| bad("ReturnCode without Code".into()))?
                .trim()
                .parse()
                .map_err(|_| bad("ReturnCode Code is not an integer".into()))?;
            let result = ResultClass::parse(
                rc.attr("Result")
                    .ok_or_else(|| bad("ReturnCode without Result".into()))?,
            )?;
            let reboot = rc
                .attr("Reboot")
                .map(|v| parse_bool("Reboot", v))
                .transpose()?;
            return_codes.push(ReturnCodeRule {
                code,
                result,
                reboot,
            });
        }
        if return_codes.is_empty() {
            return Err(bad("InstallCommand without ReturnCode".into()));
        }
        let spec = Self {
            program,
            arguments,
            reboot_by_default,
            default_result,
            return_codes,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Structural validation shared with specs built by other means.
    pub fn validate(&self) -> Result<(), HandlerError> {
        crate::download::validate_file_name(&self.program)
            .map_err(|e| HandlerError::Invalid(format!("Program: {e}")))?;
        self.argument_tokens().map(|_| ())
    }

    /// The argument vector (no program), validated.
    pub fn argument_tokens(&self) -> Result<Vec<String>, HandlerError> {
        let Some(a) = &self.arguments else {
            return Ok(Vec::new());
        };
        let tokens: Vec<String> = a
            .split(' ')
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        for t in &tokens {
            if !token_ok(t) {
                return Err(HandlerError::Invalid(format!(
                    "argument `{}` has characters outside [A-Za-z0-9/._=:-]",
                    t.escape_debug()
                )));
            }
        }
        Ok(tokens)
    }

    /// Maps a process exit code (Windows reports a `u32`; it is compared as
    /// the `i32` with the same bits, which is how the observed negative
    /// codes are written).
    pub fn classify(&self, exit_code: i32) -> Outcome {
        if let Some(rule) = self.return_codes.iter().find(|r| r.code == exit_code) {
            let class = match (rule.result, rule.reboot) {
                (ResultClass::Failed, _) => ExitClass::Failed,
                (ResultClass::Succeeded, Some(true)) => ExitClass::Reboot,
                (ResultClass::Succeeded, Some(false)) => ExitClass::Success,
                (ResultClass::Succeeded, None) => {
                    if self.reboot_by_default == Some(true) {
                        ExitClass::Reboot
                    } else {
                        ExitClass::Success
                    }
                }
            };
            return Outcome {
                class,
                matched: true,
            };
        }
        Outcome {
            class: ExitClass::Failed,
            matched: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsus_protocol::soap::{Limits, xml};

    fn spec(xml_text: &str) -> Result<CommandLineSpec, HandlerError> {
        let top = xml::parse_fragments(xml_text.as_bytes(), &Limits::default()).unwrap();
        CommandLineSpec::from_element(&top[0])
    }

    const BASE: &str = r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="AM_Delta.exe" Arguments="WD /q"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#;

    #[test]
    fn parses_the_observed_shape() {
        let s = spec(BASE).unwrap();
        assert_eq!(s.program, "AM_Delta.exe");
        assert_eq!(s.argument_tokens().unwrap(), ["WD", "/q"]);
        assert_eq!(s.classify(0).class, ExitClass::Success);
    }

    #[test]
    fn unlisted_exit_code_fails_closed() {
        let o = spec(BASE).unwrap().classify(1);
        assert_eq!(o.class, ExitClass::Failed);
        assert!(!o.matched);
    }

    #[test]
    fn negative_codes_and_reboot_rules() {
        let s = spec(
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="AM_Engine.exe" Arguments="/LastPackage"><ReturnCode Code="0" Result="Succeeded" /><ReturnCode Code="-2142207945" Result="Succeeded" Reboot="true" /></InstallCommand></HandlerSpecificData>"#,
        )
        .unwrap();
        assert_eq!(s.classify(0x8050_8037u32 as i32).class, ExitClass::Reboot);
        let f = spec(
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe"><ReturnCode Code="0" Result="Succeeded" /><ReturnCode Code="-2142207945" Result="Failed" /></InstallCommand></HandlerSpecificData>"#,
        )
        .unwrap();
        assert_eq!(f.classify(-2142207945).class, ExitClass::Failed);
        assert!(f.classify(-2142207945).matched);
    }

    #[test]
    fn reboot_by_default_is_honoured_only_for_success() {
        let s = spec(
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe" RebootByDefault="true" DefaultResult="Failed"><ReturnCode Result="Succeeded" Code="0" /></InstallCommand></HandlerSpecificData>"#,
        )
        .unwrap();
        assert_eq!(s.classify(0).class, ExitClass::Reboot);
        assert_eq!(s.classify(5).class, ExitClass::Failed);
    }

    #[test]
    fn hostile_input_is_rejected() {
        for bad in [
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="..\evil.exe"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe" Arguments="/q &amp; calc"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe" Arguments="&quot;x&quot;"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe" Arguments="%TEMP%"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe"><ReturnCode Code="0" Result="Maybe" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:Other"><InstallCommand Program="a.exe"><ReturnCode Code="0" Result="Succeeded" /></InstallCommand></HandlerSpecificData>"#,
            r#"<HandlerSpecificData type="cmd:CommandLineInstallation"><InstallCommand Program="a.exe" /></HandlerSpecificData>"#,
        ] {
            assert!(spec(bad).is_err(), "{bad}");
        }
    }
}
