#[macro_export]
macro_rules! vprintln {
    ($verbose:expr, $($args:expr),+) => {
        if $verbose {
            println!($($args),+);
        }
    };
}

#[macro_export]
macro_rules! unwrap_continue {
    ($res:expr, $cb:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                $cb(e);
                continue;
            }
        }
    };
}
