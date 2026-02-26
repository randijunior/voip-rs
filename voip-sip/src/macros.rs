macro_rules! parse_header_param {
    ($scanner:ident) => (
        $crate::macros::parse_param!(
            $scanner,
            $crate::parser::Parser::parse_ref_param,
        )
    );

    ($scanner:ident, $($name:ident = $var:expr),*) => (
        $crate::macros::parse_param!(
            $scanner,
            $crate::parser::Parser::parse_ref_param,
            $($name = $var),*
        )
    );
}

macro_rules! parse_param {
    (
        $scanner:ident,
        $func:expr,
        $($name:ident = $var:expr),*
    ) =>  {{
        $scanner.skip_ws();
        match $scanner.peek() {
            Some(b';') => {
                let mut params = $crate::message::Params::new();
                while let Some(b';') = $scanner.peek() {
                        // take ';' character
                        let _ = $scanner.read();
                        let param = $func($scanner)?;
                        $(
                            if param.0 == $name {
                                $var = param.1.map(|p| p.into());
                                $scanner.skip_ws();
                                continue;
                            }
                        )*
                        params.push(param.into());
                        $scanner.skip_ws();
                    }
                    if params.is_empty() {
                        None
                    } else {
                        Some(params)
                    }
                },
                _ => {
                    None
                }
            }
        }};
    }

macro_rules! comma_separated_header_value {
    ($scanner:ident => $body:expr) => {{
        let mut hdr_itens = Vec::with_capacity(1);
        $crate::macros::comma_separated!($scanner => {
            hdr_itens.push($body);
        });
        hdr_itens
    }};
}

macro_rules! comma_separated {
    ($scanner:ident => $body:expr) => {{
        $scanner.skip_ws();
        $body

        while let Some(b',') = $scanner.peek() {
            $scanner.read()?;
            $scanner.skip_ws();
            $body
        }
    }};
}

#[macro_export]
macro_rules! headers {
    () => (
        $crate::message::headers::Headers::new()
    );
    ($($x:expr),+ $(,)?) => (
        $crate::message::headers::Headers::from(vec![$($x),+])
    );
}

macro_rules! try_parse_hdr {
    ($header:ident, $scanner:ident) => {{
        let Ok(header) = $header::parse($scanner) else {
            let position = *$scanner.position();
            return Err(ParseError::new($crate::error::ParseErrorKind::Header, position).into());
        };
        header
    }};
}

#[macro_export]
macro_rules! filter_map_header {
    ($hdrs:expr, $header:ident) => {
        $hdrs.iter().filter_map(|hdr| {
            if let $crate::message::headers::Header::$header(v) = hdr {
                Some(v)
            } else {
                None
            }
        })
    };
}

#[macro_export]
macro_rules! find_map_header {
    ($hdrs:expr, $header:ident) => {
        $hdrs.iter().find_map(|hdr| {
            if let $crate::message::headers::Header::$header(v) = hdr {
                Some(v)
            } else {
                None
            }
        })
    };
}

#[macro_export]
macro_rules! find_map_mut_header {
    ($hdrs:expr, $header:ident) => {
        $hdrs.iter_mut().find_map(|hdr| {
            if let $crate::message::headers::Header::$header(v) = hdr {
                Some(v)
            } else {
                None
            }
        })
    };
}

pub(crate) use {
    comma_separated, comma_separated_header_value,parse_header_param, parse_param,
    try_parse_hdr,
};
pub use {filter_map_header, find_map_header, find_map_mut_header, headers};
