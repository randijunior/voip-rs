#[macro_export]
macro_rules! lookup_table {
    ($name:ident => $( $slice:expr ),+) => {
        const $name: [bool; 256] = {
            let mut arr = [false; 256];
            $(
                let mut i = 0;
                while i < $slice.len() {
                    arr[$slice[i] as usize] = true;
                    i += 1;
                }
            )*
            arr
        };
    };
}