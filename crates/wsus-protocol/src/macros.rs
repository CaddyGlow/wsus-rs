//! Declarative helpers that define wire structs and string enums.

/// Define a struct together with its `WireType` implementation.
///
/// Field kinds, in schema (`xs:sequence`) order:
/// * `req T` -- `minOccurs=1`, field type `T`
/// * `opt T` -- `minOccurs=0`, field type `Presence<T>`
/// * `req_array T` -- required wrapper of repeated items, `Vec<T>`
/// * `opt_array T` -- optional wrapper of repeated items, `Presence<Vec<T>>`
///
/// Each field is `kind name: Type => "XmlName"` and array kinds add
/// `/ "ItemName"`.
macro_rules! wire_struct {
    (
        $(#[$sm:meta])*
        pub struct $name:ident {
            $(
                $(#[$fm:meta])*
                $kind:ident $field:ident : $ty:ty => $xml:literal $(/ $item:literal)?
            ),* $(,)?
        }
        $(alternate_order [$($alternate:literal),* $(,)?];)?
    ) => {
        $(#[$sm])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $(
                $(#[$fm])*
                pub $field: wire_struct!(@ty $kind $ty),
            )*
        }

        impl $crate::soap::wire::WireType for $name {
            #[allow(unused_mut, unused_variables)]
            fn to_xml(&self, ns: &str, name: &str) -> $crate::soap::xml::Element {
                let mut e = $crate::soap::xml::Element::new(ns, name);
                $( wire_struct!(@put $kind e self.$field, $xml $($item)?); )*
                e
            }

            #[allow(unused_variables)]
            fn from_xml(
                el: &$crate::soap::xml::Element,
                ctx: &$crate::soap::wire::Ctx<'_>,
            ) -> $crate::error::Result<Self> {
                let f = ($crate::soap::wire::Fields::new(el, ctx, &[$($xml),*])
                    $(.or_else(|_| $crate::soap::wire::Fields::new(el, ctx, &[$($alternate),*])))?)?;
                Ok(Self {
                    $( $field: wire_struct!(@get $kind f $xml $($item)?), )*
                })
            }
        }
    };
    (@ty req $ty:ty) => { $ty };
    (@ty opt $ty:ty) => { $crate::soap::wire::Presence<$ty> };
    (@ty req_array $ty:ty) => { Vec<$ty> };
    (@ty opt_array $ty:ty) => { $crate::soap::wire::Presence<Vec<$ty>> };
    (@put req $e:ident $v:expr, $xml:literal) => { $crate::soap::wire::put(&mut $e, $xml, &$v) };
    (@put opt $e:ident $v:expr, $xml:literal) => { $crate::soap::wire::put_opt(&mut $e, $xml, &$v) };
    (@put req_array $e:ident $v:expr, $xml:literal $item:literal) => {
        $crate::soap::wire::put_req_array(&mut $e, $xml, $item, &$v)
    };
    (@put opt_array $e:ident $v:expr, $xml:literal $item:literal) => {
        $crate::soap::wire::put_array(&mut $e, $xml, $item, &$v)
    };
    (@get req $f:ident $xml:literal) => { $f.req($xml)? };
    (@get opt $f:ident $xml:literal) => { $f.opt($xml)? };
    (@get req_array $f:ident $xml:literal $item:literal) => { $f.req_array($xml, $item)? };
    (@get opt_array $f:ident $xml:literal $item:literal) => { $f.opt_array($xml, $item)? };
}

/// Define an enum of string values with an `Unknown` catch-all that keeps
/// unrecognised values verbatim.
macro_rules! string_enum {
    (
        $(#[$m:meta])*
        pub enum $name:ident {
            $( $(#[$vm:meta])* $var:ident = $s:literal ),* $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vm])* $var, )*
            /// A value this crate does not know, preserved verbatim.
            Unknown(String),
        }

        impl $crate::soap::wire::Scalar for $name {
            const KIND: &'static str = stringify!($name);
            fn parse(text: &str) -> Option<Self> {
                Some(match text.trim() {
                    $( $s => Self::$var, )*
                    other => Self::Unknown(other.to_owned()),
                })
            }
            fn format(&self) -> String {
                match self {
                    $( Self::$var => $s.to_owned(), )*
                    Self::Unknown(s) => s.clone(),
                }
            }
        }
    };
}

pub(crate) use string_enum;
pub(crate) use wire_struct;
